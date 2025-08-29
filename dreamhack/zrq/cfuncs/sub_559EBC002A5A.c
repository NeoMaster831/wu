void __fastcall sub_559EBC002A5A(Node *a1)
{
  Node *fd; // rbx

  fd = a1->fd->fd->fd;
  fd->content = fd->fd->fd->fd->content - fd->content;
  fd->fd->fd->fd->fd->fd->content = (size_t)malloc(0x100u);
}