void __fastcall sub_559EBC002BBD(Node *a1)
{
  signed __int64 v1; // rax

  v1 = sys_write(a1->fd->fd->fd->content, (const char *)&a1->fd->content, 1u);
  a1->fd->fd->fd->fd->content = 9;
  free(&off_559EBC20BE80);
}