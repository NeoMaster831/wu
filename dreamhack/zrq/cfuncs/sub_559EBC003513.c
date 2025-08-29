void __fastcall sub_559EBC003513(Node *a1)
{
  if ( (signed __int64)a1->fd->fd->fd->fd->content > (signed __int64)a1->fd->content )
  {
    a1->fd->fd->fd->fd->content -= 2LL;
    a1->content += 2LL;
    free(&off_559EBC20C030);
  }
}