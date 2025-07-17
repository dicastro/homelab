#include <unistd.h>
#include <stdlib.h>

int main() {
    setuid(0);
    setgid(0);
    return system("/bin/systemctl poweroff -i");
}