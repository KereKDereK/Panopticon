#include "common.h"

int pin_map(struct bpf_map *map, const char* path){
    int err;
    err = bpf_map__pin(map, path);
        if (err) {
            fprintf(stdout, "Can't pin map %s: %d\n", path, err);
            return err;
        }
    return err;
}
