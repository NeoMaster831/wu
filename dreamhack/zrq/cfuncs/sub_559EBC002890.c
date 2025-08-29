void __fastcall sub_559EBC002890(Node *a1)
{
  signed __int64 v1; // rax

  v1 = sys_write(a1->fd->fd->content, (const char *)&a1->fd->content, 1u);
  free((void *)a1->fd->fd->fd->fd->fd->fd->fd->fd->fd->content);
}