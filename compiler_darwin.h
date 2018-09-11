typedef struct {
    char *name;
    void *blob;
    int len;
} sbProfile_t;

typedef struct {

} sbParams_t;

extern sbParams_t *sandbox_create_params();
extern sbProfile_t *sandbox_compile_file(char *profile_file, sbParams_t *params, char **err);
extern sbProfile_t *sandbox_compile_named(char *profile_name, sbParams_t *params, char **err);
extern sbProfile_t *sandbox_compile_string(char *profile_string, sbParams_t *params, char **err);
extern void sandbox_free_profile(sbProfile_t *compiled_profile);
