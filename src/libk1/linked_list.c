#include <k1/linked_list.h>
#include <stdlib.h>

void k1_linked_list_append(struct k1_node **head, struct k1_node **to_append)
{
    struct k1_node **ptr_of_interest = head;

    while(*ptr_of_interest != (struct k1_node *)NULL)
        ptr_of_interest = &(*ptr_of_interest)->next;

    *(ptr_of_interest) = *to_append;
    *to_append = NULL;
}

struct k1_node *k1_make_node(void **data)
{
    struct k1_node *tmp_node = malloc(sizeof(struct k1_node));
    if(!tmp_node)
        return (struct k1_node *)NULL;

    tmp_node->next = (struct k1_node *)NULL;
    tmp_node->data = *data;
    *data = NULL;

    return tmp_node;
}

void k1_linked_list_free(struct k1_node *head)
{
    struct k1_node *current = head;
    struct k1_node *next = current->next;
    while(current != (struct k1_node *)NULL) {
        next = current->next;
        free(current->data);
        free(current);
        current = next;
    }
}
