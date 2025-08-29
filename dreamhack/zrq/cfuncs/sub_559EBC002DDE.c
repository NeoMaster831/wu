void __fastcall sub_559EBC002DDE(Node *a1)
{
  char *v1; // rsi
  signed __int64 v2; // rax

  v1 = (char *)(a1->fd->content + 16);
  v2 = sys_write(a1->fd->fd->fd->fd->fd->fd->fd->fd->fd->fd->fd->fd->content, v1, 1u);
  *(_QWORD *)v1 = a1->content;
}