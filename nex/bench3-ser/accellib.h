#include <cstddef>
#include <stdint.h>

// #define read_csr_safe(reg) ({ register long __tmp asm("a0"); \
// asm volatile ("csrr %0, " #reg : "=r"(__tmp)); \
// __tmp; })

// #define _PERF(i, append) uint64_t count_##i##_##append = read_csr_safe(cycle)

uint64_t read_ns_time();

#define _PERF(i, append) volatile uint64_t count_##i##_##append = read_ns_time()
#define PRINT_ELAPSED(i) printf("PERF %d, ns new %ld (s %ld, e %ld)\n", i, count_##i##_e-count_##i##_s, count_##i##_s, count_##i##_e) 

#define PROTOACC_OPCODE 2
#define FUNCT_SFENCE 0
#define FUNCT_PROTO_PARSE_INFO 1
#define FUNCT_DO_PROTO_PARSE 2
#define FUNCT_MEM_SETUP 3
#define FUNCT_CHECK_COMPLETION 4

#define PROTOACC_SER_OPCODE 3
#define FUNCT_SER_SFENCE 0
#define FUNCT_HASBITS_INFO 1
#define FUNCT_DO_PROTO_SERIALIZE 2
#define FUNCT_SER_MEM_SETUP 3
#define FUNCT_SER_CHECK_COMPLETION 4

void AccelSetup();
volatile char ** AccelSetupSerializer();

#define AccelParseFromString(filename, msgtype, dest, inputstr) \
    AccelParseFromString_Helper(filename##_FriendStruct_##msgtype##_ACCEL_DESCRIPTORS::msgtype##_ACCEL_DESCRIPTORS, \
        dest, inputstr, inputstr_length);

void AccelParseFromString_Helper(const void * descriptor_table_ptr, void * dest_base_addr,
                          const void* inputstr, uint64_t inputstr_length);

#define AccelSerializeToString(filename, msgtype, src) \
    AccelSerializeToString_Helper(filename##_FriendStruct_##msgtype##_ACCEL_DESCRIPTORS::msgtype##_ACCEL_DESCRIPTORS, \
        src);

void AccelSerializeToString_Helper(const void * descriptor_table_ptr, void * src_base_addr);

uint64_t block_on_completion();

volatile char * BlockOnSerializedValue(volatile char ** ptrs, int index);
size_t GetSerializedLength(volatile char ** ptrs, int index);

uintptr_t driver_initialize();
void init_memory_mapping();

void nex_jail_break();
void nex_end_jail_break();
void nex_virtual_speedup(int percentage);
void nex_end_virtual_speedup();