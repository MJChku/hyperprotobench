#include "accellib.h"
#include <bits/stdint-uintn.h>
#include <cassert>
#include <ctime>
#include <malloc.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <bits/stdint-uintn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <stdint.h>
#include <inttypes.h>
#include <iostream>
#include <stack>
#include <fstream>
#include <fcntl.h>
#include <sys/mman.h>
#include "vfio.h"
static void *reg_bar = nullptr;
static int vfio_fd = -1;

#define TURN_ON_REGS
uint64_t mem_base=0, string_base=0, output_base_1=0, output_base_2=0;


#define MEM_BASE_OFFSET 0x40000000   // 1 GB offset
#define STRING_BASE_OFFSET MEM_BASE_OFFSET+256*1024*1024 // 1.25 GB offset
#define OUTPUT_BASE_OFFSET MEM_BASE_OFFSET+400*1024*1024 // 1.x GB offset
#define MEM_SIZE (512 * 1024 * 1024)  // 512 MB

static uint32_t prev_completed_msg = 0;
// ENCODE_BASE + OFFSET should be the mem_base
// -----ENCODE_BASE + encoded addr 
// ------------------mem_base
// ENCODE_BASE and mem_base are the same
#define OFFSET (mem_base - MEM_BASE_OFFSET)
#define ENCODE_BASE mem_base - OFFSET

// #define DEBUG_PRINT(...) printf(__VA_ARGS__)
#define DEBUG_PRINT(...) 

void *MapRegister(uint32_t addr);
void init_memory_mapping();
void protoacc_copy_to_devmem(uint64_t hasbits_offset, uint64_t min_max_fieldno, uint64_t descriptor_table_addr, uint64_t src_base_addr, uint64_t* new_descriptor_table_addr, uint64_t* new_src_base_addr);

void WriteMappedReg(void* base_addr, uint32_t offset, uint32_t val) {
  *((volatile uint32_t *) (reinterpret_cast<char *>(base_addr) + offset)) = val;
}

uint32_t ReadMappedReg(void* base_addr, uint32_t offset) {
  return *((volatile uint32_t *) (reinterpret_cast<char *>(base_addr) + offset));
}

uint64_t read_ns_time(){
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

typedef struct __attribute__((packed)) ProtoAccRegs {
  uint64_t ctrl;
  uint64_t isBusy;
  uint64_t stringobj_output_addr;
  uint64_t string_ptr_output_addr;
  uint64_t hasbits_offset;
  uint64_t min_max_fieldno;
  uint64_t descriptor_table_ptr;
  uint64_t src_base_addr;
} ProtoAccRegs;

void* driver_initialize(){
   return MapRegister(0);
}

static void* acc_regs; 

#define PAGESIZE_BYTES 4096

void AccelSetupFixedAllocRegion() {
    
    DEBUG_PRINT("AccelSetupFixedAllocRegion\n");

    acc_regs = (ProtoAccRegs*)driver_initialize();

    // ROCC_INSTRUCTION(PROTOACC_OPCODE, FUNCT_SFENCE);

    size_t regionsize = sizeof(char) * (128 << 13);
    char * fixed_alloc_region = (char*)memalign(PAGESIZE_BYTES, regionsize);
    for (uint64_t i = 0; i < regionsize; i += PAGESIZE_BYTES) {
        fixed_alloc_region[i] = 0;
    }

    char * array_alloc_region = (char*)memalign(PAGESIZE_BYTES, regionsize);
    for (uint64_t i = 0; i < regionsize; i += PAGESIZE_BYTES) {
        array_alloc_region[i] = 0;
    }

    uint64_t fixed_ptr_as_int = (uint64_t)fixed_alloc_region;
    uint64_t array_ptr_as_int = (uint64_t)array_alloc_region;

    // ROCC_INSTRUCTION_SS(PROTOACC_OPCODE, fixed_ptr_as_int, array_ptr_as_int, FUNCT_MEM_SETUP);


    assert((fixed_ptr_as_int & 0x7) == 0x0);
    assert((array_ptr_as_int & 0x7) == 0x0);

    // DEBUG_PRINT("accelerator given %lld byte region, starting at 0x%016llx for fixed alloc\n", (uint64_t)regionsize, fixed_ptr_as_int);
    // DEBUG_PRINT("accelerator given %lld byte region, starting at 0x%016llx for array alloc\n", (uint64_t)regionsize, array_ptr_as_int);

}

void AccelSetup() {
    AccelSetupFixedAllocRegion();
}

volatile char ** AccelSetupFixedAllocRegionSerializer() {
    DEBUG_PRINT("AccelSetupFixedAllocRegionSerializer\n");
    // ROCC_INSTRUCTION(PROTOACC_SER_OPCODE, FUNCT_SER_SFENCE);
    acc_regs = (ProtoAccRegs*)driver_initialize();

    prev_completed_msg = ReadMappedReg(acc_regs, 0x4);

    size_t regionsize = sizeof(char) * (128 << 13);
    // char * string_alloc_region = (char*)memalign(PAGESIZE_BYTES, regionsize);
    char* string_alloc_region = (char*)output_base_1;
    // for (uint64_t i = 0; i < regionsize; i += PAGESIZE_BYTES) {
    //     string_alloc_region[i] = 0;
    // }

    uint64_t stringalloc_region_ptr_as_int = (uint64_t)string_alloc_region;
    uint64_t stringalloc_region_ptr_as_int_tail = stringalloc_region_ptr_as_int + (uint64_t)regionsize;

    uint64_t num_string_ptrs = 2048;
    size_t string_ptr_region_size = num_string_ptrs * sizeof(char*);
    // char ** stringptr_region = (char**)memalign(PAGESIZE_BYTES, string_ptr_region_size);
    char ** stringptr_region = (char**)output_base_2;
    char * stringptrcharwriter = (char*)stringptr_region;
    // for (uint64_t i = 0; i < string_ptr_region_size; i += PAGESIZE_BYTES) {
    //     stringptrcharwriter[i] = 0;
    // }
    stringptr_region[0] = (char*)stringalloc_region_ptr_as_int_tail;
    stringptr_region += 1;

    uint64_t string_ptr_region_ptr_as_int = (uint64_t)stringptr_region;

    // ROCC_INSTRUCTION_SS(PROTOACC_SER_OPCODE, stringalloc_region_ptr_as_int_tail, string_ptr_region_ptr_as_int, FUNCT_SER_MEM_SETUP);
    #ifdef TURN_ON_REGS
    string_ptr_region_ptr_as_int = string_ptr_region_ptr_as_int - OFFSET;
    stringalloc_region_ptr_as_int_tail = stringalloc_region_ptr_as_int_tail - OFFSET;
    WriteMappedReg(acc_regs, 0x28, stringalloc_region_ptr_as_int_tail & 0xffffffff);
    WriteMappedReg(acc_regs, 0x2c, (stringalloc_region_ptr_as_int_tail >> 32)& 0xffffffff);
    WriteMappedReg(acc_regs, 0x30, string_ptr_region_ptr_as_int & 0xffffffff);
    WriteMappedReg(acc_regs, 0x34, (string_ptr_region_ptr_as_int >> 32) & 0xffffffff);
    WriteMappedReg(acc_regs, 0x00, 1<<7);
    #endif

    assert((stringalloc_region_ptr_as_int_tail & 0x7) == 0x0);
    assert((string_ptr_region_ptr_as_int & 0x7) == 0x0);

    // DEBUG_PRINT("accelerator given %lld byte region, tail at 0x%016llx for string alloc\n", (uint64_t)regionsize, stringalloc_region_ptr_as_int_tail);
    // DEBUG_PRINT("accelerator given %lld byte region, starting at 0x%016llx for string ptr alloc\n", (uint64_t)string_ptr_region_size, string_ptr_region_ptr_as_int);

    return (volatile char**)stringptr_region;
}

volatile char ** AccelSetupSerializer() {
    init_memory_mapping();
    return AccelSetupFixedAllocRegionSerializer();
}

void busy_wait_for_nanoseconds(long nanoseconds) {
    struct timespec start, current, diff;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int64_t elapsed;
    do {
        clock_gettime(CLOCK_MONOTONIC, &current);
        
        // Calculate time difference
        if ((current.tv_nsec - start.tv_nsec) < 0) {
            diff.tv_sec = current.tv_sec - start.tv_sec - 1;
            diff.tv_nsec = current.tv_nsec - start.tv_nsec + 1000000000L;
        } else {
            diff.tv_sec = current.tv_sec - start.tv_sec;
            diff.tv_nsec = current.tv_nsec - start.tv_nsec;
        }

        // Convert time difference to nanoseconds
        elapsed = diff.tv_sec * 1000000000LL + diff.tv_nsec;
    } while (elapsed < nanoseconds);
}



volatile char * BlockOnSerializedValue(volatile char ** ptrs, int index) {
    uint64_t retval;
    while(1){
      uint32_t completed_msg = ReadMappedReg(acc_regs, 0x4);
      if((completed_msg - prev_completed_msg) == index+1){
        break;
      }
      // usleep(5);
      busy_wait_for_nanoseconds(5000);
    }
    return 0;
}

size_t GetSerializedLength(volatile char ** ptrs, int index) {
    return 0;
    // return (size_t)(ptrs[index-1] - ptrs[index]);
}


void AccelParseFromString_Helper(const void * descriptor_table_ptr, void * dest_base_addr,
                          const void* inputstr, uint64_t inputstr_length) {
    const void * base_ptr = inputstr;
    uint64_t input_length = inputstr_length;
    if (input_length == 0) {
        return;
    }

    uint64_t* access_descr_ptr = (uint64_t*)descriptor_table_ptr;
    uint64_t min_field_no = access_descr_ptr[3] >> 32;
    uint64_t low32_mask_internal = 0x00000000FFFFFFFFL;
    uint64_t min_field_no_and_input_length = (min_field_no << 32) | (input_length & low32_mask_internal);

    //ROCC_INSTRUCTION_SS(PROTOACC_OPCODE, descriptor_table_ptr, dest_base_addr, FUNCT_PROTO_PARSE_INFO);
    //ROCC_INSTRUCTION_SS(PROTOACC_OPCODE, base_ptr, min_field_no_and_input_length, FUNCT_DO_PROTO_PARSE);

}

uint64_t block_on_completion() {
    uint64_t retval;
    //ROCC_INSTRUCTION_D(PROTOACC_OPCODE, retval, FUNCT_CHECK_COMPLETION);
    //asm volatile ("fence");
    return retval;
}


uint64_t cur_string_available=0, cur_mem_available=0;


void AccelSerializeToString_Helper(const void * descriptor_table_ptr, void * src_base_addr) {
    DEBUG_PRINT("AccelSerializeToString_Helper\n");
    uint64_t* access_descr_ptr = (uint64_t*)descriptor_table_ptr;
    uint64_t hasbits_offset = access_descr_ptr[2];
    uint64_t min_max_fieldno = access_descr_ptr[3];
    uint64_t new_descriptor_table_addr, new_src_base_addr;
    protoacc_copy_to_devmem(hasbits_offset, min_max_fieldno, (uint64_t)descriptor_table_ptr, (uint64_t)src_base_addr, &new_descriptor_table_addr, &new_src_base_addr);
    // ROCC_INSTRUCTION_SS(PROTOACC_SER_OPCODE, hasbits_offset, min_max_fieldno, FUNCT_HASBITS_INFO);
    // ROCC_INSTRUCTION_SS(PROTOACC_SER_OPCODE, descriptor_table_ptr, src_base_addr, FUNCT_DO_PROTO_SERIALIZE);
    #ifdef TURN_ON_REGS
    uint32_t max_fieldno = min_max_fieldno & 0xFFFFFFFF;
    uint32_t min_fieldno = (min_max_fieldno >> 32) & 0xFFFFFFFF;
     
    WriteMappedReg(acc_regs, 0x8, min_fieldno);
    WriteMappedReg(acc_regs, 0xc, max_fieldno);
    WriteMappedReg(acc_regs, 0x10, new_descriptor_table_addr & 0xffffffff);
    WriteMappedReg(acc_regs, 0x14, (new_descriptor_table_addr >> 32)& 0xffffffff);
    WriteMappedReg(acc_regs, 0x18, new_src_base_addr & 0xffffffff);
    WriteMappedReg(acc_regs, 0x1c, (new_src_base_addr >> 32) & 0xffffffff);
    WriteMappedReg(acc_regs, 0x20, hasbits_offset & 0xffffffff);
    WriteMappedReg(acc_regs, 0x24, (hasbits_offset >> 32) & 0xffffffff);
    // this sets the serialize workload
    WriteMappedReg(acc_regs, 0, 1);

    // acc_regs->hasbits_offset = hasbits_offset;
    // acc_regs->min_max_fieldno = min_max_fieldno;
    // acc_regs->descriptor_table_ptr = (uint64_t)new_descriptor_table_addr;
    // acc_regs->src_base_addr = (uint64_t)new_src_base_addr;
    // acc_regs->ctrl = 1;
    #endif
    DEBUG_PRINT("AccelSerializeToString_Helper done\n");
}

uint64_t fill_normal_mem(uint64_t addr, uint64_t size){
    
    DEBUG_PRINT("fill_normal_mem %lx %lx, offset %lx \n", addr, size, cur_mem_available);

    memcpy((void*)(cur_mem_available+mem_base), (void*)addr, size);
    cur_mem_available += size;
    // return cur_mem_available+mem_base-size;
    return cur_mem_available-size+ENCODE_BASE;
    // return cur_mem_available-size;
}

uint64_t fill_string_mem(uint64_t addr, uint64_t size){
    // NOTE here we are not copying the data, just advancing the address
    // memcpy((void*)(cur_string_available+string_base), (void*) addr, size);
    cur_string_available += size;
    // return cur_string_available+string_base-size;
    return cur_string_available-size+ENCODE_BASE+string_base - mem_base;
    // return cur_string_available-size;
}

int mem_fd;

void init_memory_mapping() {

    if(mem_base != 0){
        return;
    }
    DEBUG_PRINT("Initializing memory mapping\n");

    mem_fd = open("/dev/mem", O_RDWR );
    if (mem_fd == -1) {
        perror("Error opening /dev/mem");
        exit(1);
    }
    // Map the main memory area
    mem_base = (uint64_t)mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, MEM_BASE_OFFSET);
    
    if ((void*)mem_base == MAP_FAILED) {
        perror("Error mapping /dev/mem");
        close(mem_fd);
        exit(1);
    }

    string_base = mem_base + STRING_BASE_OFFSET-MEM_BASE_OFFSET;
    output_base_1 = mem_base + OUTPUT_BASE_OFFSET - MEM_BASE_OFFSET;
    output_base_2 = mem_base + OUTPUT_BASE_OFFSET - MEM_BASE_OFFSET;
    // Map the string area
}

void cleanup_memory_mapping() {
    munmap((void*)mem_base, MEM_SIZE);
    munmap((void*)string_base, MEM_SIZE);
    close(mem_fd);
}


ssize_t read_process_memory(int fd, uintptr_t address, void *buffer, size_t size) {
   //log out to a file 
   DEBUG_PRINT("read_process_memory %lx %lx\n", address, size);
   memcpy(buffer, (void*)(address), size);
   return 0;
}


ssize_t new_read_process_memory(int fd, uintptr_t address, void *buffer, size_t size) {
   //log out to a file 
   DEBUG_PRINT("new_read_process_memory %lx %lx\n", address, size);
   memcpy(buffer, (void*)(address+OFFSET), size);
   return 0;
}

typedef enum {
    S_WAIT_CMD = 0,
    S_SCALAR_DISPATCH_REQ = 1,
    S_SCALAR_OUTPUT_DATA = 2,
    S_WRITE_KEY = 3,
    S_STRING_GETPTR = 4,
    S_STRING_GETHEADER1 = 5,
    S_STRING_GETHEADER2 = 6,
    S_STRING_RECVHEADER1 = 7,
    S_STRING_RECVHEADER2 = 8,
    S_STRING_LOADDATA = 9,
    S_STRING_WRITEKEY = 10,
    S_UNPACKED_REP_GETPTR = 11,
    S_UNPACKED_REP_GETSIZE = 12,
    S_UNPACKED_REP_RECVPTR = 13,
    S_UNPACKED_REP_RECVSIZE = 14
} SCALAR_STATES;

typedef enum {
    WIRE_TYPE_VARINT = 0,
    WIRE_TYPE_64bit = 1,
    WIRE_TYPE_LEN_DELIM = 2,
    WIRE_TYPE_START_GROUP = 3,
    WIRE_TYPE_END_GROUP = 4,
    WIRE_TYPE_32bit = 5
} WIRE_TYPES;

WIRE_TYPES wire_type_lookup[19] = {WIRE_TYPE_VARINT, WIRE_TYPE_64bit, WIRE_TYPE_32bit, WIRE_TYPE_VARINT, WIRE_TYPE_VARINT, WIRE_TYPE_VARINT, WIRE_TYPE_64bit, WIRE_TYPE_32bit, WIRE_TYPE_VARINT, WIRE_TYPE_LEN_DELIM, WIRE_TYPE_START_GROUP, WIRE_TYPE_LEN_DELIM, WIRE_TYPE_LEN_DELIM, WIRE_TYPE_VARINT, WIRE_TYPE_VARINT, WIRE_TYPE_32bit, WIRE_TYPE_64bit, WIRE_TYPE_VARINT, WIRE_TYPE_VARINT};

typedef enum {
    TYPE_DOUBLE = 1,
    TYPE_FLOAT = 2,
    TYPE_INT64 = 3,
    TYPE_UINT64 = 4,
    TYPE_INT32 = 5,
    TYPE_FIXED64 = 6,
    TYPE_FIXED32 = 7,
    TYPE_BOOL = 8,
    TYPE_STRING = 9,
    TYPE_GROUP = 10,
    TYPE_MESSAGE = 11,
    TYPE_BYTES = 12,
    TYPE_UINT32 = 13,
    TYPE_ENUM = 14,
    TYPE_SFIXED32 = 15,
    TYPE_SFIXED64 = 16,
    TYPE_SINT32 = 17,
    TYPE_SINT64 = 18,
    TYPE_fieldwidth = 5
}PROTO_TYPES;

int cpp_size[19] = {0, 3, 2, 3, 3, 2, 3, 2, 0, 3, 0, 3, 3, 2, 2, 2, 3, 2, 3};
int is_poentially_scalar[19] = {0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1};
int is_variant_signed[19] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1};


std::stack<uint64_t> size_stack;
std::stack<uint64_t> depth_stack;

static uint64_t backend_string_ptr_output_addr = 0;
static uint64_t backend_stringobj_output_addr_tail = 0;
static uint64_t frontend_stringobj_output_addr_tail = 0;

void protoacc_serialize_field(int fd, uint64_t relative_fieldno, uint64_t min_fieldno, uint64_t cpp_obj_addr, uint64_t entry_1, uint64_t entry_2){
  int descr_result_is_repeated = (entry_1 >> 63) & 1;
  int descr_result_typeinfo = (entry_1 << 1 >> 59) & 0x1F;
  // int descr_result_is_nested = descr_result_typeinfo == TYPE_MESSAGE;
  uint64_t descr_result_offset = ((entry_1 << 6) >> 6);

  uint64_t src_data_addr = cpp_obj_addr + descr_result_offset;
  int src_data_type = descr_result_typeinfo;
  uint64_t field_number = relative_fieldno + min_fieldno - 1;
  // depth is missing
  uint64_t end_of_message = relative_fieldno == 0;
  if(end_of_message){
    // !!! this is wrong
    field_number = 0;
  }

  // if end of message needs field_number will equal to parent_fieldnum

  int cpp_size_log2_reg = cpp_size[src_data_type];
  int cpp_size_nonlog2_fromreg = 1 << cpp_size_log2_reg;
  int cpp_size_nonlog2_numbits_fromreg = cpp_size_nonlog2_fromreg << 3;
  int wire_type_reg = wire_type_lookup[src_data_type];
  int is_varint_signed = is_variant_signed[src_data_type];
  int is_int32_reg = src_data_type == TYPE_INT32;
  int detailedTypeIsPotentiallyScalar = is_poentially_scalar[src_data_type];
  int is_bytes_or_string = (src_data_type == TYPE_STRING) || (src_data_type == TYPE_BYTES);
  int is_repeated = descr_result_is_repeated;
  int is_packed = 0;
  int varintDataUnsigned = !is_varint_signed;
  int varintData64bit = cpp_size_log2_reg == 3;

  int handlerState = 0;
  // S_WAIT_CMD:
//   uint128_t memread = 0;
  uint64_t memread[2] = {0, 0};

  uint64_t string_obj_ptr_reg = 0;
  uint64_t string_data_ptr_reg = 0;
  uint64_t base_addr_bytes = 0;
  uint64_t base_len = 0;
  uint64_t aligned_loadlen = 0;
  uint64_t base_addr_start_index = 0;
  uint64_t base_addr_end_index = 0;
  uint64_t base_addr_end_index_inclusive = 0;
  uint64_t extra_word = 0;
  uint64_t base_addr_bytes_aligned = 0;
  uint64_t words_to_load = 0;
  uint64_t words_to_load_minus_one = 0;

  uint64_t encoded_string_length_no_null_term_bytes_reg = 0;
  uint64_t base_addr_bytes_aligned_reg = 0;
  uint64_t words_to_load_reg = 0;
  uint64_t words_to_load_minus_one_reg_fixed = 0;
  uint64_t base_addr_start_index_reg = 0;
  uint64_t base_addr_end_index_inclusive_reg = 0;
  uint64_t string_load_respcounter = 0;

  uint64_t repeated_elems_headptr;

  int bytes_data[1000] = {0};
  int bytes_data_size = 0;
 
  int field_is_repeated = is_repeated;

  if(end_of_message){
    DEBUG_PRINT("end of message\n");
    // then write out the key 
    // https://github.com/ucb-bar/protoacc/blob/d2d69ab9b67ceae64ff5f98120ac99370f30a473/src/main/scala/memwriter_serializer.scala#L73
    // size_stack(depth) + writes_input_IF_Q.io.deq.bits.validbytes is merged together
    // finally the parent needs to add the size_stack(depth) to the size_stack(depth-1)
    handlerState = S_WRITE_KEY;

  }else{
    if(detailedTypeIsPotentiallyScalar && !is_repeated){
      handlerState = S_SCALAR_DISPATCH_REQ;
    }else if(is_bytes_or_string && !is_repeated){
      handlerState = S_STRING_GETPTR;
    }else if((detailedTypeIsPotentiallyScalar || is_bytes_or_string) && is_repeated){
      handlerState = S_UNPACKED_REP_GETPTR;
    }else{
      assert(0);
    }
  }

  uint64_t repeated_obj_size = 0;
  uint64_t nonrepeated_obj_size = 0;

  while(1){
    switch(handlerState){
      case S_SCALAR_DISPATCH_REQ:{
        bytes_data[bytes_data_size++] = 1<<cpp_size_log2_reg;
        DEBUG_PRINT("S_SCALAR_DISPATCH_REQ, size %d \n", 1<<cpp_size_log2_reg);
        assert(cpp_size_log2_reg <= 16);
        // read_process_memory(fd, src_data_addr, &memread, 1<<cpp_size_log2_reg);

        handlerState = S_SCALAR_OUTPUT_DATA;
        nonrepeated_obj_size += 1<<cpp_size_log2_reg;
      }
      break;
      case S_SCALAR_OUTPUT_DATA:{
        DEBUG_PRINT("S_SCALAR_OUTPUT_DATA\n");
        if(!(is_repeated && is_packed)){
          handlerState = S_WRITE_KEY;
        }else{
          if(src_data_addr == repeated_elems_headptr){
            handlerState = S_WRITE_KEY;
          }else{
            src_data_addr = src_data_addr - cpp_size_nonlog2_fromreg;
            handlerState = S_SCALAR_DISPATCH_REQ;
          }
        }
      }
      break;
      case S_WRITE_KEY:{

        DEBUG_PRINT("S_WRITE_KEY\n");
       
        int is_unpacked_repeated = is_repeated && !is_packed;
        if(!is_unpacked_repeated){
           // for json
          handlerState = S_WAIT_CMD;
        }else {
          if(src_data_addr == repeated_elems_headptr){
            
            handlerState = S_WAIT_CMD;
          }else{
            DEBUG_PRINT("repeated fileds %lx %lx\n", src_data_addr, repeated_elems_headptr);
            src_data_addr = src_data_addr - cpp_size_nonlog2_fromreg;
            handlerState = S_SCALAR_DISPATCH_REQ;
          }
        }
      }
      break;
    
      case S_STRING_GETPTR: {
        DEBUG_PRINT("S_STRING_GETPTR src_data_addr %p, size %d \n", (void*)src_data_addr, 1<<cpp_size_log2_reg);
        new_read_process_memory(fd, src_data_addr, &memread, 1<<cpp_size_log2_reg);
        handlerState = S_STRING_GETHEADER1;
      }
      break;
      case S_STRING_GETHEADER1:{
        DEBUG_PRINT("S_STRING_GETHEADER1\n");
        string_obj_ptr_reg = memread[0];
        read_process_memory(fd, string_obj_ptr_reg, &string_data_ptr_reg, 8);

        handlerState = S_STRING_GETHEADER2;
      }
      break;
      case S_STRING_GETHEADER2:{
        DEBUG_PRINT("S_STRING_GETHEADER2\n");
        // https://github.com/ucb-bar/protoacc/blob/d2d69ab9b67ceae64ff5f98120ac99370f30a473/src/main/scala/fieldhandler_serializer.scala#L347
        read_process_memory(fd, string_obj_ptr_reg+8, &base_len, 8);
        handlerState = S_STRING_RECVHEADER1;
      }
      break;
      case S_STRING_RECVHEADER1:{
        DEBUG_PRINT("S_STRING_RECVHEADER1\n");
        handlerState = S_STRING_RECVHEADER2;
      }
      break;
      case S_STRING_RECVHEADER2:{

        // for json

        DEBUG_PRINT("S_STRING_RECVHEADER2, base_len %ld\n", base_len);
        base_addr_bytes = string_data_ptr_reg;
        //base_len = base_len;
        base_addr_start_index = base_addr_bytes & 0xF;
        aligned_loadlen = base_len + base_addr_start_index;
        base_addr_end_index = aligned_loadlen & 0xF;
        base_addr_end_index_inclusive = (aligned_loadlen - 1) & 0xF;
        extra_word = (aligned_loadlen & 0xF) != 0;
        base_addr_bytes_aligned = (base_addr_bytes >> 4) << 4;
        words_to_load = (aligned_loadlen >> 4) + extra_word;

        nonrepeated_obj_size += 1<<cpp_size_log2_reg;
        
        uint64_t new_base_addr_bytes_aligned_reg = fill_string_mem(base_addr_bytes_aligned, words_to_load << 4);
        DEBUG_PRINT("new_base_addr_bytes_aligned_reg %lx, words_to_load %ld \n", new_base_addr_bytes_aligned_reg, words_to_load);
        // *(uint64_t*)string_obj_ptr_reg = new_base_addr_bytes_aligned_reg >> 4 << 4 | (string_data_ptr_reg & 0xF);

        uint64_t new_string_obj_ptr_reg = fill_normal_mem(string_obj_ptr_reg, 16);
         *(uint64_t*)(new_string_obj_ptr_reg+OFFSET) = new_base_addr_bytes_aligned_reg >> 4 << 4 | (string_data_ptr_reg & 0xF);

        
        *(uint64_t*)(src_data_addr+OFFSET) = new_string_obj_ptr_reg;
        DEBUG_PRINT("src %lx, new_string_obj_ptr_reg %lx\n", new_string_obj_ptr_reg, src_data_addr+OFFSET);

        handlerState = S_STRING_LOADDATA;
      }
      break;
      case S_STRING_LOADDATA:{
        DEBUG_PRINT("S_STRING_LOADDATA words_to_load_reg %ld, string_load_respcounter %ld, words_to_load_minus_one %ld\n", words_to_load_reg, string_load_respcounter, words_to_load_minus_one_reg_fixed);
        
        handlerState = S_STRING_WRITEKEY;
        string_load_respcounter = 0;
      }
      break;
      case S_STRING_WRITEKEY:{
        DEBUG_PRINT("S_STRING_WRITEKEY\n");
        int is_unpacked_repeated = is_repeated && !is_packed;
        if(!is_unpacked_repeated){
            // for json
            bytes_data_size = 0;
            handlerState = S_WAIT_CMD;
        }else{
          if(src_data_addr == repeated_elems_headptr){
            // for json
            bytes_data_size = 0;
            handlerState = S_WAIT_CMD;
          }else{
            src_data_addr = src_data_addr - cpp_size_nonlog2_fromreg;
            handlerState = S_STRING_GETPTR;
          }
        }
      }
      break;
      case S_UNPACKED_REP_GETPTR:{
        DEBUG_PRINT("S_UNPACKED_REP_GETPTR\n");
        if(is_bytes_or_string){
          new_read_process_memory(fd, src_data_addr+8, &repeated_elems_headptr, 8);
        }else{
          new_read_process_memory(fd, src_data_addr, &repeated_elems_headptr, 8);
        }
        handlerState = S_UNPACKED_REP_GETSIZE;
      }
      break;
      case S_UNPACKED_REP_GETSIZE:{
        DEBUG_PRINT("S_UNPACKED_REP_GETSIZE\n");
        if(is_bytes_or_string){
          new_read_process_memory(fd, src_data_addr, &memread, 8);
        }else{
          new_read_process_memory(fd, src_data_addr-8, &memread, 8);
        }
        handlerState = S_UNPACKED_REP_RECVPTR;
      }
      break;
      case S_UNPACKED_REP_RECVPTR:{
        DEBUG_PRINT("S_UNPACKED_REP_RECVPTR\n");
        if(is_bytes_or_string){
          repeated_elems_headptr += 8;
        }
        handlerState = S_UNPACKED_REP_RECVSIZE;
      }
      break;
      case S_UNPACKED_REP_RECVSIZE:{
        DEBUG_PRINT("S_UNPACKED_REP_RECVSIZE\n");
        int num_elems = (int)(memread[0] & 0xFFFFFFFF);
        uint64_t new_repeated_elems_headptr;

        new_repeated_elems_headptr = fill_normal_mem(repeated_elems_headptr, num_elems<<cpp_size_log2_reg );
        repeated_elems_headptr = new_repeated_elems_headptr;
        if(is_bytes_or_string){
          *(uint64_t*)(src_data_addr + OFFSET + 8) = repeated_elems_headptr - 8;
        }else{
          *(uint64_t*)(src_data_addr + OFFSET) = repeated_elems_headptr;
        }

        uint64_t ptr_to_last_elem = repeated_elems_headptr + ((num_elems-1) << cpp_size_log2_reg); 

        src_data_addr = ptr_to_last_elem;

        DEBUG_PRINT("S_UNPACKED_REP_RECVSIZE, num_elems %d, new_repeated_elems_headptr %lx, src_data_addr %lx\n", num_elems, new_repeated_elems_headptr, src_data_addr);
        if(is_bytes_or_string){
          handlerState = S_STRING_GETPTR;
        }else{
          handlerState = S_SCALAR_DISPATCH_REQ;
        }
      }
      break;
      default:
        assert(0);
    }

    if(handlerState == S_WAIT_CMD){
      DEBUG_PRINT("End of field handle\n");
      break;
    }
  }
}

static uint64_t depth = 0;
void parse_message_to_json(int mem_fd, uint64_t descriptor_table_addr, uint64_t cpp_obj_addr, uint64_t* new_descriptor_table_addr, uint64_t* new_cpp_obj_addr) {
    
    DEBUG_PRINT("=== messsage start ===\n");
    // Read the message
   // header has 64B

    uint8_t* header = (uint8_t*) malloc(64);
    read_process_memory(mem_fd, descriptor_table_addr, header, 64);
    
    //first 8 bytes 
    void* vptr = (void*)((uint64_t*)header)[0];
    
    DEBUG_PRINT("cpp_obj_addr %lx and vptr %lx\n", cpp_obj_addr, (uint64_t)vptr);
    // assert((uint64_t)vptr == cpp_obj_addr);
    //second 8bytes
    uint64_t size = ((uint64_t*)header)[1];

    *new_cpp_obj_addr = fill_normal_mem((uint64_t)cpp_obj_addr, size);

    cpp_obj_addr = *new_cpp_obj_addr;
    
    //third 8bytes
    uint64_t hasbits_off = ((uint64_t*)header)[2];
    
    // fouth 8bytes
    uint64_t min_max_field = ((uint64_t*)header)[3];

    DEBUG_PRINT("cpp_obj_addr %lx\n", cpp_obj_addr);
    // DEBUG_PRINT("Descriptor table: vptr %lx size %lx hasbits_off%lx\n", ((uint64_t*)buffer)[0], ((uint64_t*)buffer)[1], ((uint64_t*)buffer)[2]);
    DEBUG_PRINT("hasbits : %lx\n", hasbits_off);
    DEBUG_PRINT("min_max_fieldno : %lx\n", min_max_field);

    uint64_t max_fieldno = min_max_field & 0x00000000FFFFFFFFL;
    uint64_t min_fieldno = min_max_field >> 32; 
    DEBUG_PRINT("max_field %ld, min_field %ld\n", max_fieldno, min_fieldno);
    uint64_t depth_plus_one = max_fieldno - min_fieldno + 1;
    uint64_t hasbits_addr = (uint64_t)(cpp_obj_addr + hasbits_off);
    

    // every field is 128bits = 16B = 2^4

    // or hasbits_max_bitoffset 
    uint64_t current_has_bits_next_bitoffset = max_fieldno - min_fieldno + 1;
    uint64_t has_bits_max_bitoffset = current_has_bits_next_bitoffset;
    // val next_next_field_offset = (current_has_bits_next_bitoffset % 32.U) + 1.U
    // current_has_bits_next_bitoffset := current_has_bits_next_bitoffset - next_next_field_offset

    // divide by 32 to get the array start
    // load 4 bytes for 32 bits of has bits
    uint64_t hasbits_array_index; 
    uint64_t hasbits_request_addr;
    uint64_t is_submessage_request_addr;
    uint64_t hasbits_resp_fieldno;

    // hasbit first bit is not used 
    uint64_t num_fields_this_hasbits, fieldno_offset_from_tail=0;

    #define ACCESS_ONE_BIT(data, bit_pos) ((data >> (bit_pos)) & 1)

    #define ACCESS_FIELD_START(filedno)  (((filedno-1) << 4)+32+descriptor_table_addr)
    
    // 32B header + every field 16B + submessage 4B for each 32 fields
    uint64_t total_size = 32 + ((max_fieldno - min_fieldno + 1) << 4) + (has_bits_max_bitoffset/32+1)*4;
    *new_descriptor_table_addr = fill_normal_mem(descriptor_table_addr, total_size);
    descriptor_table_addr = *new_descriptor_table_addr;
    uint64_t is_submessage_base = ((max_fieldno - min_fieldno + 1) << 4)+32+descriptor_table_addr;
   
    while(1){
        // load max 32 fields
        uint32_t hasbits_4bytes=0;
        uint32_t is_submessage_4bytes=0;
        num_fields_this_hasbits = current_has_bits_next_bitoffset % 32 + 1;
        hasbits_array_index = current_has_bits_next_bitoffset >> 5;
        hasbits_request_addr = (hasbits_array_index << 2) + hasbits_addr;
        is_submessage_request_addr = (hasbits_array_index << 2) + is_submessage_base;
        new_read_process_memory(mem_fd, hasbits_request_addr, &hasbits_4bytes, 4);
        new_read_process_memory(mem_fd, is_submessage_request_addr, &is_submessage_4bytes, 4);
        DEBUG_PRINT("hasbits addr %p, hasbits_4bytes %x, is_submessage_4bytes %x\n", (void*)hasbits_request_addr, hasbits_4bytes, is_submessage_4bytes);
        int hasbits_done_chunk = 0;
        while(!hasbits_done_chunk && num_fields_this_hasbits > 0){
          hasbits_resp_fieldno = has_bits_max_bitoffset-fieldno_offset_from_tail;
          int hasbit_for_current_fieldno = ACCESS_ONE_BIT(hasbits_4bytes, hasbits_resp_fieldno%32) || hasbits_resp_fieldno == 0;
          int is_submessage_bit_for_current_fieldno = ACCESS_ONE_BIT(is_submessage_4bytes, hasbits_resp_fieldno%32);
          int current_field_is_present_and_submessage =  hasbit_for_current_fieldno && is_submessage_bit_for_current_fieldno;
          // process the current field
          if(hasbit_for_current_fieldno == 1 && is_submessage_bit_for_current_fieldno == 0){
            DEBUG_PRINT("I get a field %ld, is present %d, is submessage %d \n", hasbits_resp_fieldno+min_fieldno-1, hasbit_for_current_fieldno, is_submessage_bit_for_current_fieldno);
            uint64_t field_addr = ACCESS_FIELD_START(hasbits_resp_fieldno);
            uint64_t field_entry[2];
            new_read_process_memory(mem_fd, field_addr, &field_entry, 16);
            protoacc_serialize_field(mem_fd, hasbits_resp_fieldno, min_fieldno, cpp_obj_addr, field_entry[0], field_entry[1]);
          }
          fieldno_offset_from_tail++;
          int hasbits_chunk_end = fieldno_offset_from_tail == num_fields_this_hasbits;
          // hasbits_done_chunk = hasbits_chunk_end || current_field_is_present_and_submessage;
          if(current_field_is_present_and_submessage){
            uint64_t field_addr = ACCESS_FIELD_START(hasbits_resp_fieldno);
            uint64_t buffer[2];
            new_read_process_memory(mem_fd, field_addr, &buffer, 16);
            uint64_t descriptor_table_addr = buffer[1];
            // https://github.com/ucb-bar/protoacc/blob/master/src/main/scala/descriptortablehandler_serializer.scala#L471
            uint64_t submessage_cpp_obj_addr=0;
            new_read_process_memory(mem_fd, cpp_obj_addr + ((buffer[0] << 6) >> 6), &submessage_cpp_obj_addr, 8);;
            uint64_t new_des, new_cpp;
            parse_message_to_json(mem_fd, descriptor_table_addr, submessage_cpp_obj_addr, &new_des, &new_cpp);
            // write back the new descriptor table addr
            *(uint64_t*)(OFFSET+field_addr+8) = new_des;
            *(uint64_t*)(OFFSET+cpp_obj_addr + ((buffer[0] << 6) >> 6)) = new_cpp;
          }

          hasbits_done_chunk = hasbits_chunk_end;
        }
        fieldno_offset_from_tail = 0;
        if(current_has_bits_next_bitoffset <= 31){
          // done already
          break;
        }
        current_has_bits_next_bitoffset = current_has_bits_next_bitoffset - (current_has_bits_next_bitoffset%32+1);
        has_bits_max_bitoffset = current_has_bits_next_bitoffset;
        DEBUG_PRINT("current_has_bits_next_bitoffset %ld\n", current_has_bits_next_bitoffset);
    }
    
    DEBUG_PRINT("=== messsage ends ===\n");
    return ;
    //is_submessage_base_addr := (((max_fieldno - min_fieldno) + 1.U) << 4) + 32.U + io.serializer_cmd_in.bits.descriptor_table_addr
    // 2^4 is 16 bytes, 32 bytes for the header, 
    // each entry now is 128bits = 16B
}

void protoacc_copy_to_devmem(uint64_t hasbits_offset, uint64_t min_max_fieldno, uint64_t descriptor_table_addr, uint64_t src_base_addr, uint64_t* new_descriptor_table_addr, uint64_t* new_cpp_obj_addr){
  
  //measure time it takes in ns, use high resolution timer
  // struct timespec start, end;
  // clock_gettime(CLOCK_MONOTONIC, &start);
  parse_message_to_json(0, descriptor_table_addr, src_base_addr, new_descriptor_table_addr, new_cpp_obj_addr);
  // clock_gettime(CLOCK_MONOTONIC, &end);
  // printf("=== protoacc_copy_to_devmem Time taken %ld (ns)\n", end.tv_sec*1000000000+end.tv_nsec - start.tv_sec*1000000000-start.tv_nsec);
  // fflush(stdout);
  return;
  
}

void *MapRegister(uint32_t addr) {
  if (!reg_bar) {
    char *device = std::getenv("PROTOACC_DEVICE");
    if (device == nullptr) {
      std::cerr << "PROTOACC_DEVICE is not set" << std::endl;
      abort();
    }
    if ((vfio_fd = vfio_init(device)) < 0) {
      std::cerr << "vfio init failed" << std::endl;
      abort();
    }

    size_t reg_len = 0;
    if (vfio_map_region(vfio_fd, 0, &reg_bar, &reg_len)) {
      std::cerr << "vfio map region failed" << std::endl;
      abort();
    }

    if (vfio_busmaster_enable(vfio_fd)) {
      std::cerr << "vfio busmaster enable failed" << std::endl;
      abort();
    }

    //std::cerr << "vfio registers mapped (len = " << reg_len << ")" << std::endl;
  }

  return (uint8_t *) reg_bar + addr;
}
