void __fastcall sub_559EBC002CC7(Node *a1)
{
  a1->fd->content += a1->fd->fd->fd->content;
  free((void *)a1->content);
}