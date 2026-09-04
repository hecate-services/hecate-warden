%%% @doc Publishing what the warden sees onto the mesh.
%%%
%%% The warden is a producer: it observes, and it tells the federation. These are
%%% integration FACTS, not domain events — the warden holds no store. The durable
%%% record (the evidence chain an abuse report is built from) is made on the beam
%%% side, in hecate-spartan, when a general's process manager hears these facts.
%%% Degrades silently while the mesh is dark: an unreachable mesh must never stop
%%% the tarpit from doing its job.
-module(hecate_warden_facts).

-export([threat/1, ensnared/2, presence/0]).

-define(THREAT_TOPIC,   <<"warden/threats">>).
-define(ENSNARED_TOPIC, <<"warden/ensnared">>).
-define(PRESENCE_TOPIC, <<"warden/presence">>).

%% @doc A real attacker was seen on the box's real service (from the auth log).
%% Breadth: this is every attacker, and it is what correlates across countries.
-spec threat(map()) -> ok.
threat(Sighting) when is_map(Sighting) ->
    publish(?THREAT_TOPIC, Sighting#{type => threat_sighted,
                                     warden => reporter(),
                                     tenant_id => tenant_id(),
                                     label => label(),
                                     at => at(Sighting)}).

%% @doc We held an attacker in the tarpit for HeldMs and they gave up. Depth:
%% the ones who took the bait, and the satisfying number — attacker-time wasted.
-spec ensnared(binary(), non_neg_integer()) -> ok.
ensnared(Ip, HeldMs) when is_binary(Ip) ->
    publish(?ENSNARED_TOPIC, #{type => attacker_ensnared,
                               warden => reporter(),
                               tenant_id => tenant_id(),
                               label => label(),
                               source_ip => Ip,
                               held_ms => HeldMs,
                               at => erlang:system_time(millisecond)}).

%% @doc Heartbeat: the warden announces its own presence so the map can build
%% its roster live (no hard-coded box list). Carries the box's declared
%% coordinates when set — SELF-ASSERTED, not verified: fine for our own fleet
%% and for deliberately placing a marker, but an untrusted warden could claim
%% any location. Coordinates are micro-degree integers (the mesh drops raw
%% floats). A warden with no declared coordinates still announces — it is listed
%% as online without a marker.
-spec presence() -> ok.
presence() ->
    publish(?PRESENCE_TOPIC, with_coords(#{type => warden_present,
                                           warden => reporter(),
                                           tenant_id => tenant_id(),
                                           label => label(),
                                           tarpit => tarpit_on(),
                                           at => erlang:system_time(millisecond)})).

%% --- Internal ---

with_coords(Fact) ->
    maybe_coord(maybe_coord(Fact, lat_e6, "HECATE_WARDEN_LAT_E6"),
                lng_e6, "HECATE_WARDEN_LNG_E6").

maybe_coord(Fact, Key, EnvVar) ->
    put_coord(Fact, Key, os:getenv(EnvVar)).

put_coord(Fact, _Key, false) -> Fact;
put_coord(Fact, _Key, "")    -> Fact;
put_coord(Fact, Key, S) ->
    case string:to_integer(S) of
        {I, _} when is_integer(I) -> Fact#{Key => I};
        _                          -> Fact
    end.

%% Whether this warden is running the tarpit (decoy ports bound) or is a pure
%% sensing sidecar. Carried on presence so the map can distinguish a decoy node.
%% Returns 1/0, not a bare atom: this mesh's wire format has no boolean type
%% (every other fact in this ecosystem follows the same 0/1 convention), and a
%% raw `true' atom here was the reason warden-fr-paris (the one box that is
%% ever tarpit=true) never actually landed a presence fact -- every
%% tarpit=false warden's atom apparently limped through the wire as a string,
%% but true did not, so the one honeypot box silently never appeared on the
%% Vigil map. Confirmed live 2026-09-04: watching warden/presence directly
%% showed 10/10 sensing wardens present, zero from madrid, and every one of
%% those 10 carried `"tarpit":"false"' -- a string, not a boolean, the
%% tell-tale sign of exactly this bug.
-spec tarpit_on() -> 0 | 1.
tarpit_on() ->
    case application:get_env(hecate_warden, tarpit_ports) of
        {ok, [_ | _]} -> 1;
        _             -> 0
    end.

publish(Topic, Fact) ->
    case {hecate_om:macula_client(), hecate_om_identity:realm()} of
        {{ok, Pool}, {ok, Realm}} ->
            published(Topic, catch macula:publish(Pool, Realm, Topic, Fact));
        _DarkOrNoRealm ->
            ok
    end.

%% A refused frame used to vanish here. Since macula 6.0.0 an unsendable frame
%% fails its SENDER with a reason instead of killing the shared peering
%% connection, so the reason exists and there is no longer any excuse for
%% discarding it: a warden whose facts are being rejected looks exactly like a
%% warden with nothing to report. Say which.
published(_Topic, ok) ->
    ok;
published(Topic, Refused) ->
    logger:warning("[warden] publish ~s REFUSED: ~p", [Topic, Refused]),
    ok.

%% A human-readable name for this warden ("helsinki"), so a sighting says WHERE
%% it was seen without anyone decoding a DID. It is also the stable identity the
%% sentinel correlates on: the reporter DID is ephemeral (regenerated on
%% restart), the label is not.
label() ->
    case application:get_env(hecate_warden, label) of
        {ok, L} when is_list(L), L =/= "", L =/= "unknown" -> list_to_binary(L);
        {ok, L} when is_binary(L), L =/= <<>>, L =/= <<"unknown">> -> L;
        _ -> undefined
    end.

%% WHO operates this warden — the third-party (or our own) id that a warden is
%% run under. `undefined' when unset: an unattributed contributor to the commons.
%% Distinct from `label' (which box) and `reporter' (ephemeral DID): tenant_id is
%% stable and names the ORG, so the commons can attribute and a tenant can filter
%% to their own fleet without the correlation ever being scoped to one tenant.
tenant_id() ->
    case application:get_env(hecate_warden, tenant_id) of
        {ok, T} when is_list(T), T =/= "", T =/= "unknown" -> list_to_binary(T);
        {ok, T} when is_binary(T), T =/= <<>>, T =/= <<"unknown">> -> T;
        _ -> undefined
    end.

%% This warden's own service identity (hex-encoded Ed25519 public key) — so a
%% sighting also carries cryptographic provenance of who reported it.
%%
%% Was `hecate_om_identity:service_did()' — confirmed via `git log -S' across
%% this repo's ENTIRE history that no such function has ever existed in
%% hecate_om, at any version, in any module. Not a removed API: hecate-warden's
%% own first commit (8a34d26) called a function that was never real, silently
%% swallowed by the try/catch below ever since. Real accessor is
%% `hecate_om:keypair/0' (the facade), same public key macula's own node_id/1
%% is defined as verbatim (macula_identity.erl: `node_id(#{public := Pub}) ->
%% Pub'), hex-encoded to match every other pubkey-as-identity display in this
%% ecosystem (macula-e2e, macula-realm's LoadMonitor, etc.).
reporter() ->
    case hecate_om:keypair() of
        {ok, KeyPair} -> binary:encode_hex(macula_identity:public(KeyPair));
        {error, _}    -> undefined
    end.

at(#{at := At}) when is_integer(At) -> At;
at(_)                               -> erlang:system_time(millisecond).
