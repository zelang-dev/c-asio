#include "assertions.h"

string gai = "dns.google";
string gni = "8.8.8.8";

void_t worker_misc(params_t args) {
    ASSERT_WORKER(($size(args) > 2));
    delay(args[0].u_int);
    ASSERT_WORKER(is_str_in("addrinfo, nameinfo", args[1].char_ptr));
    return args[2].char_ptr;
}

TEST(get_addrinfo) {
    dnsinfo_t *dns = nullptr;
    string ip = nullptr;
    rid_t res = go(worker_misc, 3, 1000, "addrinfo", "finish");
    ASSERT_TRUE(is_addrinfo(dns = get_addrinfo(gai, "http", 1, kv(ai_flags, AI_CANONNAME | AI_PASSIVE | AF_INET))));
    ASSERT_FALSE(result_is_ready(res));
    while (!result_is_ready(res))
        yield();

    ASSERT_TRUE(result_is_ready(res));
    ASSERT_STR(result_for(res).char_ptr, "finish");
    ASSERT_STR(gai, dns->ip_name);
    ASSERT_NOTNULL((ip = (string)addrinfo_ip(dns)));
    if (dns->is_ip6)
        ASSERT_TRUE((is_str_in(ip, "8844")));
    else
        ASSERT_TRUE((is_str_in(ip, "8.8")));

    ASSERT_TRUE((dns->count > 2));

    return 0;
}

TEST(get_nameinfo) {
    nameinfo_t *name = nullptr;
    rid_t res = go(worker_misc, 3, 800, "nameinfo", "finish");
    ASSERT_TRUE(is_nameinfo(name = get_nameinfo(gni, 443, 0)));
    ASSERT_FALSE(result_is_ready(res));
    while (!result_is_ready(res)) {
        yield();
    }

    ASSERT_TRUE(result_is_ready(res));
    ASSERT_STR(result_for(res).char_ptr, "finish");
    ASSERT_STR(gai, name->host);
    ASSERT_STR("https", name->service);

    return 0;
}

TEST(list) {
    int result = 0;

    EXEC_TEST(get_addrinfo);
    EXEC_TEST(get_nameinfo);

    return result;
}

int uv_main(int argc, char **argv) {
    TEST_FUNC(list());
}