#include "mem.h"
#include "mem_internals.h"
#include "util.h"
#include <unistd.h>

#include <assert.h>

#define TEST_MALLOC_SIZE 256

void debug(const char *fmt, ...);

struct block_header *get_block_header(void *ptr) {
    return (struct block_header *) (((uint8_t *)ptr) - offsetof(struct block_header, contents));
}

void test_simple_alloc( void ) {
    struct block_header *a = heap_init(REGION_MIN_SIZE);

    assert(a);

    void *ptr = _malloc(TEST_MALLOC_SIZE);

    struct block_header *b1 = get_block_header(ptr);

    assert(b1->is_free != true);
    assert(b1->capacity.bytes == TEST_MALLOC_SIZE);

    heap_term();
}


void test_free_one_block( void ) {
    struct block_header *a = heap_init(REGION_MIN_SIZE);

    assert(a);

    void *ptr1 = _malloc(TEST_MALLOC_SIZE);
    void *ptr2 = _malloc(TEST_MALLOC_SIZE);
    void *ptr3 = _malloc(TEST_MALLOC_SIZE);

    struct block_header *b1 = get_block_header(ptr1);
    struct block_header *b2 = get_block_header(ptr2);
    struct block_header *b3 = get_block_header(ptr3);

    _free(b2);
    assert(b1->is_free != true);
    assert(b2->is_free == true);
    assert(b3->is_free != true);

    heap_term();
}

void test_free_multiple_blocks( void ) {
    struct block_header *a = heap_init(REGION_MIN_SIZE);

    assert(a);

    void *ptr1 = _malloc(TEST_MALLOC_SIZE);
    void *ptr2 = _malloc(TEST_MALLOC_SIZE);
    void *ptr3 = _malloc(TEST_MALLOC_SIZE);

    struct block_header *b1 = get_block_header(ptr1);
    struct block_header *b2 = get_block_header(ptr2);
    struct block_header *b3 = get_block_header(ptr3);

    _free(b3);
    assert(b1->is_free != true);
    assert(b2->is_free != true);
    assert(b3->is_free == true);

    _free(b2);
    assert(b1->is_free != true);
    assert(b2->is_free == true);
    assert(b2->capacity.bytes == offsetof(struct block_header, contents) + TEST_MALLOC_SIZE * 2);

    heap_term();
}

void test_grow_heap() {
    struct block_header *a = heap_init(REGION_MIN_SIZE);

    assert(a);

    void *ptr = _malloc(REGION_MIN_SIZE);

    struct block_header *b = get_block_header(ptr);
    assert(b->capacity.bytes == REGION_MIN_SIZE);
    assert(size_from_capacity(b->capacity).bytes > REGION_MIN_SIZE);

    heap_term();
}

int main( void ) {
    test_simple_alloc();
    test_free_one_block();
    test_free_multiple_blocks();
    test_grow_heap();

    return 0;
}