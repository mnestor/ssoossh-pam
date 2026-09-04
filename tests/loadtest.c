/* loadtest checks the things about a built module that can be checked
 * without root: that it actually loads, that both PAM entry points resolve
 * at runtime, and that nothing else does.
 *
 * `make check-symbols` reads the symbol table statically. This runs the
 * dynamic loader over the module instead, so it also catches a missing
 * DT_NEEDED, a failed constructor, and a symbol that is present in the
 * table but unresolvable in practice.
 *
 * What it deliberately does not do is call pam_sm_authenticate. That needs
 * a live pam_handle_t, which needs a real pam.d stack, which needs root --
 * tests/pamtest.c and tests/README.md cover that half.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#ifdef __APPLE__
#    define MODULE_DEFAULT "./pam_ssoossh.bundle"
#else
#    define MODULE_DEFAULT "./pam_ssoossh.so"
#endif

/* Symbols that must resolve. */
static const char *const wanted[] = {
    "pam_sm_authenticate",
    "pam_sm_setcred",
};

/* Symbols that must NOT resolve: internals that would collide inside sudo
 * if the visibility settings or the version script ever stopped working.
 * Extend this as the module grows -- a vendored library's entry points are
 * the ones worth naming here. */
static const char *const forbidden[] = {
    "ssoossh_log_version",
    "ssoossh_infof",
    "ssoossh_debugf",
};

int main(int argc, char **argv)
{
    const char *path = (argc > 1) ? argv[1] : MODULE_DEFAULT;
    int failures = 0;
    void *h;

    /* RTLD_NOW so an unresolvable symbol surfaces here rather than at the
     * first authentication, and RTLD_LOCAL to match how libpam loads a
     * module: nothing it carries should enter the global namespace. */
    h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (h == NULL) {
        fprintf(stderr, "loadtest: dlopen(%s): %s\n", path, dlerror());
        return 1;
    }

    for (size_t i = 0; i < sizeof(wanted) / sizeof(wanted[0]); i++) {
        (void)dlerror();
        if (dlsym(h, wanted[i]) == NULL) {
            fprintf(stderr, "loadtest: %s did not resolve: %s\n", wanted[i],
                    dlerror());
            failures++;
        }
    }

    for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); i++) {
        (void)dlerror();
        if (dlsym(h, forbidden[i]) != NULL) {
            fprintf(stderr, "loadtest: %s is visible and must not be\n",
                    forbidden[i]);
            failures++;
        }
    }

    if (dlclose(h) != 0) {
        /* Not fatal, but worth reporting: being unloadable is one of the
         * properties this module has that the Go build did not. */
        fprintf(stderr, "loadtest: dlclose: %s\n", dlerror());
        failures++;
    }

    if (failures != 0) {
        fprintf(stderr, "loadtest: %d failure(s)\n", failures);
        return 1;
    }
    printf("loadtest: ok (%s)\n", path);
    return 0;
}
