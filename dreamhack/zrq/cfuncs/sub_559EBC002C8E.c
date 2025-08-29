void __fastcall sub_559EBC002C8E(Node *a1)
{
  if ( sys_chdir((const char *)&a1->content) )
    free(&off_559EBC20C840);
}