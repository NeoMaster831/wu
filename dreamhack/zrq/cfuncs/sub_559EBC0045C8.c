void __fastcall sub_559EBC0045C8(Node *a1)
{
  Node *fd; // rbx

  fd = a1->fd->fd->fd;
  fd->fd->content = fd->content + 120 * ((signed __int64)fd->fd->fd->content / 21) - 48;
  fd->content -= 120LL;
}