%%% @doc Hecate Warden — implements the hecate_om_service behaviour.
%%%
%%% The deceptive threshold guard. It runs as a sidecar to macula-station on the
%%% public boxes, which take tens of thousands of intrusion attempts a day. Its
%%% job is not to block anyone — a blocklist just sends the attacker elsewhere.
%%% Its job is to WASTE their time and LEARN what they want, and to tell the rest
%%% of the federation what it sees.
%%%
%%% Two senses, one actuator (in v1):
%%%   - the auth-log sensor reads REAL attacks on the box's real sshd (breadth:
%%%     every attacker, the cross-border correlation, the numbers);
%%%   - the tarpit is a decoy that accepts connections and holds them open,
%%%     dribbling an endless fake SSH banner, so a scanner sits there for hours
%%%     (depth: who took the bait, and how long we held them).
%%% Both publish facts to the mesh; the generals on the beam side reason about
%%% them. The immutable evidence chain lives in hecate-spartan, off this box.
%%%
%%% STORELESS: no store_id/0 + data_dir/0, so hecate_om:boot/1 wires the mesh but
%%% starts no reckon-db. This box is the most-attacked in the fleet; it holds the
%%% least.
-module(hecate_warden_service).
-behaviour(hecate_om_service).

-export([info/0, start/1, stop/1, health/0, capabilities/0, identity_spec/0]).

info() ->
    #{name        => <<"hecate-warden">>,
      version     => <<"0.1.0">>,
      description => <<"Deceptive threshold guard for the public boxes">>}.

start(_Opts) ->
    hecate_warden_sup:start_link().

stop(_State) ->
    ok.

%% Health is the SENSOR's health, asserted rather than assumed.
%%
%% This used to return a bare `ok' under a comment claiming it was green "once
%% the sensor is tailing". It checked nothing. On 2026-07-26 logrotate replaced
%% auth.log under every warden in the fleet, all nine went blind, and all nine
%% went on reporting healthy for two days while the boxes were being attacked.
%% A container that says it is fine while sensing nothing is worse than one that
%% crashes, because nothing ever looks at it again.
health() ->
    sensing(catch sense_auth_log:status()).

%% Not attached to anything: the path is missing or unreadable. Usually the
%% mount. Nothing this warden reports can be trusted, so do not say ok.
sensing(#{attached := false, path := Path}) ->
    {down, {auth_log_unreadable, Path}};
%% Attached, has read before, and has now been quiet far longer than any real
%% gap on a public box (these take tens of thousands of attempts a day, so the
%% log advances many times a minute). This is the blind-but-alive state.
sensing(#{silent_ms := Silent}) when is_integer(Silent) ->
    quiet(Silent >= silence_limit_ms(), Silent);
%% Attached but has never read a byte since boot. Deliberately FAILS OPEN: a
%% warden freshly started on a genuinely quiet box must not cry broken.
sensing(#{}) ->
    ok;
%% The sensor did not answer at all (dead, or wedged past the call timeout).
sensing(_Unavailable) ->
    {down, sensor_unavailable}.

quiet(true, Silent)   -> {degraded, {auth_log_silent_ms, Silent}};
quiet(false, _Silent) -> ok.

%% One hour. Long enough that no real lull on an attacked box trips it, short
%% enough that a rotation-blinded sensor is caught the same morning instead of
%% two days later.
silence_limit_ms() ->
    application:get_env(hecate_warden, auth_log_silence_ms, 3600000).

%% What the warden announces it can do. It reports threats and it ensnares —
%% nothing that reaches toward an attacker, nothing that could lock the operator
%% out. The whole point is that the menu of possible actions is small and safe.
capabilities() ->
    [<<"warden.report_threat">>, <<"warden.ensnare">>].

%% The UCAN the warden asks the realm to mint: authority to publish on its own
%% threat topics, and NOTHING else. If this box is popped, that is the entire
%% blast radius — a threat reporter for one location.
identity_spec() ->
    #{scope     => <<"warden">>,
      actions   => [<<"report">>],
      resources => [<<"warden/*">>],
      ttl_days  => 30}.
