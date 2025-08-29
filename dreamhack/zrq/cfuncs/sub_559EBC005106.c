void __fastcall sub_559EBC005106(Node *a1)
{
  signed __int64 v1; // rax

  v1 = sys_fcntl(0, 4u, a1->fd->content | a1->content);
  if ( !a1->fd->content )
    free(&off_559EBC20BC10);
}