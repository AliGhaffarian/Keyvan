#ifndef K1_LINKED_LIST
#define K1_LINKED_LIST

struct k1_node {
    struct k1_node *next;
    void *data;
};

void linked_list_append(struct k1_node **, struct k1_node **);
struct k1_node *make_node(void **);
void linked_list_free(struct k1_node *);
#endif
