void __fastcall sub_559EBC002D0F(Node *a1)
{
  *(_QWORD *)(a1->fd->content + 32) &= (1 << a1->fd->fd->content) - 1;
  a1->fd->fd->content -= 8LL;
  free((void *)a1->content);
}