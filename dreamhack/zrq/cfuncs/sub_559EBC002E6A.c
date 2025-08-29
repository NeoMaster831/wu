void __fastcall sub_559EBC002E6A(Node *a1)
{
  *(_DWORD *)(a1->content + 12) = a1->fd->fd->fd->fd->content;
  tcsetattr(0, 0, (const struct termios *)a1->content);
  a1->fd->content = 0;
  free(&off_559EBC20C0F0);
}