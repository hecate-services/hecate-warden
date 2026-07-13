%%% @doc The tarpit's cruelty, pinned.
-module(tarpit_tests).
-include_lib("eunit/include/eunit.hrl").

%% A junk pre-banner line must NEVER begin with "SSH-": that string is what ends
%% the game and lets the client's handshake proceed. If it ever leaks in, the
%% tarpit stops holding anyone.
never_sends_ssh_banner_test() ->
    [begin
         Line = tarpit_connection:junk_line(),
         ?assertNotMatch(<<"SSH-", _/binary>>, Line),
         ?assertMatch({_, _}, binary:match(Line, <<"\r\n">>))
     end || _ <- lists:seq(1, 2000)],
    ok.

%% The auth-log parser: a real failed-password line yields the source IP and the
%% username tried; unrelated lines are skipped.
parse_failed_password_test() ->
    L = <<"Jul 13 12:00:01 host sshd[1]: Failed password for root from "
          "203.0.113.7 port 4021 ssh2">>,
    ?assertEqual({ok, <<"203.0.113.7">>, <<"root">>}, sense_auth_log:parse(L)).

parse_invalid_user_test() ->
    L = <<"Jul 13 12:00:02 host sshd[1]: Invalid user admin from 198.51.100.9">>,
    ?assertEqual({ok, <<"198.51.100.9">>, <<"admin">>}, sense_auth_log:parse(L)).

parse_ignores_noise_test() ->
    ?assertEqual(skip, sense_auth_log:parse(
        <<"Jul 13 12:00:03 host systemd[1]: Started Session 5.">>)).
