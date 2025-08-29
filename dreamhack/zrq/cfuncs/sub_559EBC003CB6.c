void __fastcall sub_559EBC003CB6(Node *a1)
{
  if ( sys_stat((const char *)a1->content, (struct stat *)a1->fd->content) )
    free(&off_559EBC20C840);
}