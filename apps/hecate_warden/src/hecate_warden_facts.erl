%%% @doc Publishing what the warden sees onto the mesh.
%%%
%%% The warden is a producer: it observes, and it tells the federation. These are
%%% integration FACTS, not domain events — the warden holds no store. The durable
%%% record (the evidence chain an abuse report is built from) is made on the beam
%%% side, in hecate-spartan, when a general's process manager hears these facts.
%%% Degrades silently while the mesh is dark: an unreachable mesh must never stop
%%% the tarpit from doing its job.
-module(hecate_warden_facts).

-export([threat/1, ensnared/2]).

-define(THREAT_TOPIC,   <<"warden/threats">>).
-define(ENSNARED_TOPIC, <<"warden/ensnared">>).

%% @doc A real attacker was seen on the box's real service (from the auth log).
%% Breadth: this is every attacker, and it is what correlates across countries.
-spec threat(map()) -> ok.
threat(Sighting) when is_map(Sighting) ->
    publish(?THREAT_TOPIC, Sighting#{type => threat_sighted,
                                     warden => reporter(),
                                     label => label(),
                                     at => at(Sighting)}).

%% @doc We held an attacker in the tarpit for HeldMs and they gave up. Depth:
%% the ones who took the bait, and the satisfying number — attacker-time wasted.
-spec ensnared(binary(), non_neg_integer()) -> ok.
ensnared(Ip, HeldMs) when is_binary(Ip) ->
    publish(?ENSNARED_TOPIC, #{type => attacker_ensnared,
                               warden => reporter(),
                               label => label(),
                               source_ip => Ip,
                               held_ms => HeldMs,
                               at => erlang:system_time(millisecond)}).

%% --- Internal ---

publish(Topic, Fact) ->
    case {hecate_om:macula_client(), hecate_om_identity:realm()} of
        {{ok, Pool}, {ok, Realm}} ->
            catch macula:publish(Pool, Realm, Topic, Fact),
            ok;
        _DarkOrNoRealm ->
            ok
    end.

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

%% This warden's own service DID — so a sighting also carries cryptographic
%% provenance of who reported it.
reporter() ->
    try hecate_om_identity:service_did()
    catch _:_ -> undefined
    end.

at(#{at := At}) when is_integer(At) -> At;
at(_)                               -> erlang:system_time(millisecond).
