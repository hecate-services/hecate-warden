%%% @doc The warden's health is the SENSOR's health.
%%%
%%% health/0 returned a bare ok for the whole of the warden's life, under a
%%% comment claiming it went green "once the sensor is tailing". It checked
%%% nothing, so when the fleet went blind on 2026-07-26 every container went on
%%% reporting healthy for two days. These pin each state it can now report.
-module(hecate_warden_service_tests).
-include_lib("eunit/include/eunit.hrl").

health_test_() ->
    {foreach, fun setup/0, fun cleanup/1,
     [fun attached_but_never_read_fails_open/1,
      fun reading_is_healthy/1,
      fun silence_past_the_limit_is_degraded/1,
      fun an_unreadable_log_is_down/1,
      fun a_dead_sensor_is_down/1]}.

setup() ->
    Dir = filename:join(["/tmp", "warden-health-" ++ integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    Path = filename:join(Dir, "auth.log"),
    ok = file:write_file(Path, <<>>),
    ok = application:set_env(hecate_warden, auth_log, Path),
    ok = application:set_env(hecate_warden, auth_log_silence_ms, 3600000),
    #{dir => Dir, path => Path}.

cleanup(#{dir := Dir}) ->
    stop(whereis(sense_auth_log)),
    application:unset_env(hecate_warden, auth_log_silence_ms),
    _ = os:cmd("rm -rf " ++ Dir),
    ok.

stop(undefined) -> ok;
stop(Pid)       -> gen_server:stop(Pid).

%% A warden freshly started on a genuinely quiet box has read nothing yet. That
%% is not a fault, and reporting it as one would make the signal useless.
attached_but_never_read_fails_open(_Ctx) ->
    fun() ->
        start_sensor(),
        ?assertEqual(ok, hecate_warden_service:health())
    end.

reading_is_healthy(#{path := Path}) ->
    fun() ->
        start_sensor(),
        append(Path, failed_auth_line(<<"203.0.113.10">>)),
        poll(),
        ?assertEqual(ok, hecate_warden_service:health())
    end.

%% THE ONE THAT MATTERED. Alive, attached, and reading nothing. With the limit
%% dropped to zero, any completed read is already "too long ago", which is the
%% blind-but-healthy state the fleet sat in.
silence_past_the_limit_is_degraded(#{path := Path}) ->
    fun() ->
        start_sensor(),
        append(Path, failed_auth_line(<<"203.0.113.20">>)),
        poll(),
        ok = application:set_env(hecate_warden, auth_log_silence_ms, 0),
        ?assertMatch({degraded, {auth_log_silent_ms, _}}, hecate_warden_service:health())
    end.

%% No log at the path at all. In production this is the mount being wrong, which
%% is precisely how the outage started.
an_unreadable_log_is_down(#{dir := Dir}) ->
    fun() ->
        Missing = filename:join(Dir, "no-such-auth.log"),
        ok = application:set_env(hecate_warden, auth_log, Missing),
        start_sensor(),
        ?assertEqual({down, {auth_log_unreadable, Missing}}, hecate_warden_service:health())
    end.

a_dead_sensor_is_down(_Ctx) ->
    fun() ->
        start_sensor(),
        gen_server:stop(whereis(sense_auth_log)),
        ?assertEqual({down, sensor_unavailable}, hecate_warden_service:health())
    end.

%% --- helpers ---

start_sensor() ->
    {ok, _} = sense_auth_log:start_link(),
    poll().

poll() ->
    sense_auth_log ! poll,
    _ = sys:get_state(sense_auth_log),
    ok.

append(Path, Data) ->
    {ok, Fd} = file:open(Path, [append, binary, raw]),
    ok = file:write(Fd, Data),
    ok = file:close(Fd).

failed_auth_line(Ip) ->
    iolist_to_binary(["Jul 28 04:00:00 host sshd[1]: Failed password for root from ",
                      Ip, " port 4021 ssh2\n"]).
