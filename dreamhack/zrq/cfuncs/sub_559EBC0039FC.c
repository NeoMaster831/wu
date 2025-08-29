void __fastcall sub_559EBC0039FC(Node *a1)
{
  if ( sys_write(1u, (const char *)&a1->content, 2u) != 2 )
    free(&off_559EBC20C840);
}