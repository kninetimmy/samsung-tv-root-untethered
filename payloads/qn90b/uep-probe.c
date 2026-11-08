/* Task 25 unsigned native probe.
 *
 * Observable effects: one marker line on stdout (fd 1), exit status 42.
 * Nothing else. No libc, no loader, no device-side dependencies: Linux
 * syscalls only, so the trial does not depend on any userspace library
 * version on the TV.
 *
 * Build with arm-none-eabi-gcc 12.3.1 (already installed):
 *
 *   arm-none-eabi-gcc -nostdlib -static -Os -marm -march=armv7-a \
 *       -fno-stack-protector -fno-builtin -Wl,-e,_start \
 *       -o uep-probe.elf uep-probe.c
 *
 * Deliberately unsigned; that is the property under test.
 */

#define SYS_WRITE 4
#define SYS_EXIT_GROUP 248

static long syscall3(long number, long arg0, long arg1, long arg2)
{
    register long r7 __asm__("r7") = number;
    register long r0 __asm__("r0") = arg0;
    register long r1 __asm__("r1") = arg1;
    register long r2 __asm__("r2") = arg2;
    __asm__ volatile("svc 0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory");
    return r0;
}

void _start(void)
{
    static const char marker[] = "QN90B_UEP_NATIVE_PROBE_OK\n";
    syscall3(SYS_WRITE, 1, (long)marker, sizeof(marker) - 1);
    syscall3(SYS_EXIT_GROUP, 42, 0, 0);
    for (;;) {
        /* exit_group does not return */
    }
}
