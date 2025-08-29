void __fastcall sub_559EBC004A75(Node *a1)
{
  a1->fd->fd->fd->fd->fd->content += *(unsigned __int16 *)(a1->fd->fd->fd->fd->fd->content + 16);
  a1->fd->fd->content = a1->fd->fd->fd->fd->fd->content + 18;
  if ( (signed __int64)a1->fd->fd->fd->fd->fd->content >= (signed __int64)a1->fd->fd->fd->fd->content )
    free(&off_559EBC20C4B0);
}