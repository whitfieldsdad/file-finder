rule Signed_MSI
{
   strings:
       $msi = { D0 CF 11 E0 A1 B1 1A E1 }  // MSI HEADER
      $MsiCLSID = {84 10 0C 00 00 00 00 00 C0 00 00 00 00 00 00 46 }  //CLSID OF MSI
       $tst = {4D 00 73 00 69 00 44 00 69 00 67 00 69 00 74 00 61 00 6c 00 53 00 69 00 67 00 6e 00 61 00 74 00 75 00 72 00 65}  //MSI Digital Signature     
   condition:
      $msi at 0 and ($tst and $MsiCLSID at (((uint32(0x30)+1)*(1 << uint16(0x1e)))+0x50) and uint8(((uint32(0x30)+1)*(1 << uint16(0x1e)))+0x42) == 5)
}