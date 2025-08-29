void __fastcall sub_559EBC003288(Node *a1)
{
  Node *fd; // rbx

  fd = a1->fd->fd->fd->fd->fd;
  fd->fd->content += a1->content;
  a1->content += fd->content;
  a1->fd = (Node *)((unsigned __int64)a1->fd ^ (unsigned __int64)&off_559EBC20BEE0 ^ (unsigned __int64)&off_559EBC20CDB0);
}