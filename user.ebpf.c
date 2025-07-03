#define _GNU_SOURCE
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <limits.h>

#define         BPF_MAP_NAME    "cgroup_id_map"

const char      *bpf_progs[] = {"block_setuider", "block_setreuider", "block_setresuider"};
#define         NUM_OF_PROGS    (sizeof(bpf_progs)/sizeof(bpf_progs[0]))

#define         CGROUP_PATH         "/sys/fs/cgroup/"
#define         CGROUP_PATH_LEN     (sizeof(CGROUP_PATH))
#define         CGROUP_PROCS_F      "cgroup.procs"
#define         CGROUP_PROCS_F_LEN  (sizeof(CGROUP_PROCS_F))

int get_cgroup_id(const char *path, __u64 *cgid) {
    struct stat sb;

    if (stat(path, &sb) == -1) {
        perror("stat");
        exit(EXIT_FAILURE);
    }
    
    *cgid = (uintmax_t) sb.st_ino;
    return 0;
}

int main(int argc, char **argv) {

    __u64 cgroup_id = 0;

    if (argc < 3 || (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))) {
        printf("usage is: sudo ./bpfsbox <new_cgroup_name> process_pid ...\n");
        return 1;
    } 
    
    if (argc >= 3) { 
        
        int cgroup_name_len = sizeof(argv[1]);
        char *cgroup_name = argv[1];
        char *cgroup_full_path = calloc(CGROUP_PATH_LEN + sizeof(argv[1]) + 1, sizeof(char)); // intilizes it and adds '\0' at the end
        
        snprintf(cgroup_full_path, CGROUP_PATH_LEN + cgroup_name_len, "%s%s", CGROUP_PATH, cgroup_name);
        
        // mkdir(); cgroup_path. No nested directories, this is not `mkdir -p`!
        // if directory doesn't exist create it
        if (!access(cgroup_full_path, F_OK))
            printf("skipping directory creation, it already exists\n");
        else if (mkdir(cgroup_full_path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)) {// directories owned by root in cgroup fs has mode 755
            printf("Directory creation in the cgroup fs failed!\n");
            perror(cgroup_full_path);
            return 1;
        }
        
        // get cgroup id of cgroup_path
        if (get_cgroup_id(cgroup_full_path, &cgroup_id) != 0) {
            printf("Couldn't get cgroup id of the provided path at %s\n", cgroup_full_path);
            return 1;
        }

        FILE *pf;
        int len = strlen(cgroup_full_path);
        // check the trailing /, if it is not there added it
        if (cgroup_full_path[len-1] != '/') {
            if(!realloc(cgroup_full_path, len+2)) {
                perror("realloc");
                return 1;
            }
            cgroup_full_path[len] = '/';
            cgroup_full_path[len+1] = '\0';
        }
        
        len = strlen(cgroup_full_path);
        int cat_len = len + CGROUP_PROCS_F_LEN;
        // save the path to the cgroups.procs file in cgroup_procs_path
        char cgroup_procs_path[cat_len + 1];
        snprintf(cgroup_procs_path, cat_len, "%s%s", cgroup_full_path, CGROUP_PROCS_F);

        // open it in appended+ mode, otherwise it won't work in the loop
        pf = fopen(cgroup_procs_path, "a+");
        if (!pf) {
            perror("Failed to open file");
            return 1;
        }

        char *pid_str;
        int pid;
        int pid_ok;
        int nb_wrtn = 0;
        // check whether the provided pids are numerics and don't overflow pid's allowed value. 
        for (int i = 2; i < argc; i++) {
            pid_ok = 1; 
            pid_str = argv[i];
            for (int n = 0; pid_str[n] != '\0'; n++) {
                if (pid_str[n] < '0' || pid_str[n] > '9') {
                    printf("%s contains non numeric character(s), skipping\n", pid_str);
                    pid_ok = 0;
                    break;
                }
            }
            if (pid_ok) {
                sscanf(pid_str, "%d", &pid);
                if (errno == ENOMEM) {
                    printf("out of memory, skipping\n");
                    continue;
                }
                if (pid <= 0 || pid == INT_MAX) {
                    printf("provided pid [%s] is too big to be a pid, skipping\n", pid_str);
                    continue;
                }
            }
            if (pid_ok) {
                // write the PID to the cgroup.procs file
                int n = fprintf(pf, "%d\n", pid);
                if (n < 0) {
                    perror("Error during writing to the cgroup.procs file. skipping to the next pid\n");
                } else {
                    nb_wrtn += n;
                }
            }
        }

        fclose(pf);
        free(cgroup_full_path);

        if (nb_wrtn == 0) {
            printf("%s is empty, exiting.\n", cgroup_procs_path);
            return 1;
        }
    }

    int err = 0;

    // open the backend
    struct bpf_object *obj = bpf_object__open_file("sandbox_uid.ebpf.o", NULL);
    if (!obj) {
        printf("Couldn't load the ebpf kernel object\n");
        return 1;
    }
    
    // load the object
    err = bpf_object__load(obj);
    if (err) {
        printf("Failed to load the object 'sandbox_uid.ebpf.o'\n");
        return 1;
    }

    // initialize bpf_links array with 0
    struct bpf_link *bpf_prog_links[NUM_OF_PROGS + 1] = {0};

    // find and attach all three programs or quit!
    for (int i = 0; i < NUM_OF_PROGS; i++) {
        // find the program
        struct bpf_program *bpf_prog = bpf_object__find_program_by_name(obj, bpf_progs[i]);
        if (!bpf_prog) {
            printf("Failed to find the program '%s'\n", bpf_progs[i]);
            return 1;
        }

        // attach the program
        struct bpf_link *bpf_l = bpf_program__attach(bpf_prog);
        if (!bpf_l) {
            printf("Couldn't attach the program '%s'\n", bpf_progs[i]);
            return 1;
        } else {
            bpf_prog_links[i] = bpf_l;
            printf("attached: %s\n", bpf_progs[i]);
        }
    }

    // find the map
    struct bpf_map *cgroup_id_map = bpf_object__find_map_by_name(obj, BPF_MAP_NAME);
    // get the maps's fd
    int map_fd = bpf_map__fd(cgroup_id_map);
    __u32 key = 0;  

    if (map_fd && cgroup_id) {
        // update cgroup_id_map with just obtained cgroup_id
        err = bpf_map_update_elem(map_fd, &key, &cgroup_id, BPF_ANY);
        if (err != 0) {
            printf("Couldn't update the map: %s with the cgroup id", BPF_MAP_NAME);
            return 1;
        }
    } else {
        // something went wrong
        if (!map_fd)
            printf("Couldn't get the descriptor of the map: '%s'\n", BPF_MAP_NAME);
        if (!cgroup_id)
            printf("Couldn't get the cgroup id of newly created cgroup: '%s'\n", argv[1]);
        printf("exiting!\n");
        return 1;
    }

    while(1)
        sleep(1);

    return 0;
}
