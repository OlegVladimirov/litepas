echo ""; # & cls & powershell -sta -ex bypass -nop "gc .\%~nx0 | Out-String | iex" & exit
#    --- begin parameters ------------------------------------------------------
#    Don't use <# multiline powershell comment #>.
$salt = 'uYg67$%96)#&ZxDdh';
$suffix = 'Aa1,';
#    --- end parameters --------------------------------------------------------

$helpTextRus = @'
 It's script for store passwords.
 It's recommended to store info in format 'username@service'.
 Avaliable commands:
 :lite username@service                                    Short alternative :l
   Get passwords without using external file litepas.dat
   Example: :lite jimmy@wikipedia.org
      as a result password will be copied into clipboard.
 :put username@service                                     Short alternative :p
   Store encoded password in litepas.dat. If password field is empty it will be
   generated. Password cann't be paste from clipboard.
   Example: :put jimmy@wikipedia.org
      as a result password will be stored in litepas.dat.
 :get username@service                                     Short alternative :g
   Read password from litepas.dat. Similar records avaliable.
   Example 1: :get jimmy@wikipedia.org
      as a result password will be copied into clipboard.
   Example 2: :get wiki
      as a result all records containing 'wiki' will be found. If it's only
      one record - password will be copied into clipboard
   Example 3: :get *
      as a result all records from in litepas.dat will be shown.
 :delete username@service                                  Short alternative :d
   Delete records from litepas.dat.
 :masterpassword                                           Short alternative :m
   Change master password
 :help                                                     Short alternative :h
   Show this help.
 :quit                                                     Short alternative :q
   Quit.

 There are avaliable two parameters, so every user can change individually - 
 salt and suffix. Use text editor for change it.
 Licence BSD 3-Clause, Oleg Vladimirov.
'@;

Function GetPassword ($pMasterPasswordSecure, $pUsernameAtService, $pSalt) {
   # Generate password and return it.
   # Input: pMasterPasswordSecure AsSecureString, pUsernameAtService String, pSalt String.
   # Output: String.
   # ---------------------------------------------------------------------------
   $hash = [System.Security.Cryptography.HashAlgorithm]::Create('SHA1');
   $num20 = $hash.ComputeHash(
              [System.Text.Encoding]::UTF8.GetBytes(
                 [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pMasterPasswordSecure)
                 ) + $pUsernameAtService + $pSalt));
   [System.Int32] $letter = 0;
   [System.String] $allLetters = '';
   For($i = 0; $i -lt 26; $i++) {
      if($i -lt 20) {
         # 6 higher bits from every byte
         $letter = ([System.Int32] $num20[$i] - [System.Int32] $num20[$i] % 4) / 4;
      }
      else {
         # 21-th it's 2 lowest bits from 1, 2, and 3 number
         # 22-th it's 2 lowest bits from 4, 5, and 6 number
         # 23 ...
         $letter = ([System.Int32] $num20[$i - 20] % 4 ) +
                   ([System.Int32] $num20[$i - 20 + 1] % 4 ) * 4 +
                   ([System.Int32] $num20[$i - 20 + 2] % 4 ) * 16
      }
      # Let's shift codes to actual range
      $letter += 65;
      if(91 .. 96 -contains $letter) {$letter -= 43}; # 48 .. 53
      if($letter -ge 123) {$letter -= 69}; # 58 .. 63 => 123 .. 128 => 54 .. 59
      if(58 .. 59 -contains $letter) {$letter = 95};
      $allLetters += [char] $letter;
   }
   $allLetters;
}

function WriteXor($pString1, $pString2) {
   # Input 2 string for xor them byte by byte.
   # Output xored string encoded in base64.
   # ---------------------------------------------------------------------------
      $enc = [system.Text.Encoding]::ASCII;
      $data1 = $enc.GetBytes($pString1);
      $data2 = $enc.GetBytes($pString2);
      $data3 = 1 .. [System.Math]::Max($data1.length, $data2.length);
      for($i = 0; $i -lt $data3.length; $i++) {
         $data3[$i] = (
            $(If($i -lt $data1.length) {$data1[$i]} else {0}) -bxor
            $(If($i -lt $data2.length) {$data2[$i]} else {0})
         );
      }
      [System.Convert]::ToBase64String($data3);
}

function ReadXor($pString, $pStringBase64) {
   # Input 1 normal string and 1 string encoded in base64.
   # Function will xor them byte by byte.
   # Output xored string.
   # ---------------------------------------------------------------------------
      $enc = [system.Text.Encoding]::ASCII;
      $data1 = $enc.GetBytes($pString);
      $data2 = [System.Convert]::FromBase64String($pStringBase64);
      $data3 = 1 .. [System.Math]::Max($data1.length, $data2.length);
      for($i = 0; $i -lt $data3.length; $i++) {
         $data3[$i] = (
            $(If($i -lt $data1.length) {$data1[$i]} else {0}) -bxor
            $(If($i -lt $data2.length) {$data2[$i]} else {0})
         );
      }
      $enc.GetString($data3);
}

function Main() {
   # ---------------------------------------------------------------------------
   $masterPasswordSecure = Read-Host 'Enter your master-password' -AsSecureString;
   $nextIneration = $True;

   if(Test-Path litepas.dat) {
      if(Test-Path variable:\dataStore) {Remove-Variable dataStore};
      $dataStore = Import-Clixml -path litepas.dat;
      if($dataStore.ContainsKey('masterPassword')){
         if(
              (ReadXor (GetPassword $masterPasswordSecure 'masterPassword' $salt) $dataStore.masterPassword) `
              -eq 'masterPassword'
         ){
            Write-Host 'Master-password from litepas.dat is verifyed.';
         } else {
            Write-Host 'Bad master-password (errorcode 001).';
            $nextIneration = $False;
         }
      } else {
         Write-Host 'Bad file litepas.dat  (errorcode 002).';
         $nextIneration = $False;
      }
   } else {
      $masterPasswordSecureShadow = Read-Host 'There is no way to verify your' `
         'master-password from extern file litepas.dat. Plese enter' `
         'it again to be shure it correct'  -AsSecureString;
      if(
           (GetPassword $masterPasswordSecure ' ' ' ') -ne
           (GetPassword $masterPasswordSecureShadow ' ' ' ')
      ) {
         Write-Host 'The second master-password is differ. (errorcode 003).';
         $nextIneration = $False;
      }
      Remove-Variable masterPasswordSecureShadow;
   }

   While ($nextIneration) {

      $input = Read-Host 'litepas>';

      $inpAction = $input.split(' ')[0];
      $inpUsernameAtService = $input.split(' ')[1];

      Switch($inpAction) {
         ':drop'   {}
         ':d'      {$inpAction = ':drop'}
         ':delete' {$inpAction = ':drop'}

         ':get'    {}
         ':g'      {$inpAction = ':get'}
         ':show'   {$inpAction = ':get'}
         ':read'   {$inpAction = ':get'}

         ':help'   {}
         ':h'      {$inpAction = ':help'}
         'help'    {$inpAction = ':help'}
         
         ':lite'   {}
         ':l'      {$inpAction = ':lite'}

         ':masterpassword' {}
         ':m'      {$inpAction = ':masterpassword'}

         ':put'    {}
         ':p'      {$inpAction = ':put'}
         ':store'  {$inpAction = ':put'}

         ':quit'   {}
         ':q'      {$inpAction = ':quit'}
         ':exit'   {$inpAction = ':quit'}
         ':bye'    {$inpAction = ':quit'}
      }

      if(
         ($input.split(' ')[2] -ne $null) -or `
         ((':quit', ':masterpassword' -contains $inpAction) -and ($inpUsernameAtService -ne $null)) -or `
         ((':drop', ':get', ':lite', ':put' -contains $inpAction) -and ($inpUsernameAtService -eq $null))
      ) {
         $inpAction = ':unknown'
      }

      # to use [Windows.Forms.Clipboard]::SetText()
      Add-Type -AssemblyName System.Windows.Forms;

      Switch($inpAction) {
         ':drop' {
            if(Test-Path litepas.dat) {
               if(Test-Path variable:\dataStore) {Remove-Variable dataStore};
               $dataStore = Import-Clixml -path litepas.dat;
            } else {
               Write-Host 'File litepas.dat not existed. Nothing to delete.';
               Break;
            }
            $itWasFound = @();
            $dataStore.GetEnumerator() | `
               Sort-Object Name | `
               Where-Object {$_.Name -like '*' + $inpUsernameAtService + '*' `
                  -and $_.Name -ne 'masterPassword'} | `
               ForEach-Object { `
                  $itWasFound += $_.Name `
               };
            Switch($itWasFound.Count) {
               0 {
                  Write-Host 'Record similar to' $inpUsernameAtService 'not exists in litepas.dat.';
                  $confirmation = 'no';
               }
               1 {
                  $inpUsernameAtService = $itWasFound[0];
                  $confirmation =
                     Read-Host `
                        'Are you really want do delete' $inpUsernameAtService `
                        'in you litepas.dat (type ''yes'')?'
               }
               Default {
                  Write-Host 'Record' $inpUsernameAtService 'not exists in litepas.dat. Similar records:';
                  Write-Host $itWasFound;
                  $confirmation = 'no';
               }
            }
            if($confirmation -eq 'yes') {
               $dataStore.Remove($inpUsernameAtService)
               Export-Clixml -path litepas.dat -inputObject $dataStore;
               Write-Host 'Record' $inpUsernameAtService 'was deleted.';
            } else {
               Write-Host 'Not saved.'
            }
         }

         ':get' {
            if(Test-Path litepas.dat) {
               if(Test-Path variable:\dataStore) {Remove-Variable dataStore};
               $dataStore = Import-Clixml -path litepas.dat
               $itWasFound = @();
               $dataStore.GetEnumerator() | `
                  Sort-Object Name | `
                  Where-Object {$_.Name -like '*' + $inpUsernameAtService + '*' `
                     -and $_.Name -ne 'masterPassword'} | `
                  ForEach-Object { `
                     $itWasFound += $_.Name `
                  }
               Switch($itWasFound.Count) {
                  0 {
                     Write-Host 'Record similar to' $inpUsernameAtService 'not exists in litepas.dat.';
                     $confirmation = 'no';
                  }
                  1 {
                     $inpUsernameAtService = $itWasFound[0];
                     $confirmation = 'yes';
                  }
                  Default {
                     Write-Host 'Record' $inpUsernameAtService 'not exists in litepas.dat. Similar records:';
                     Write-Host $itWasFound;
                     $confirmation = 'no';
                  }
               }
               if($confirmation -eq 'yes'){
                  [Windows.Forms.Clipboard]::SetText((
                     ReadXor (GetPassword $masterPasswordSecure $inpUsernameAtService $salt) `
                        $dataStore.$inpUsernameAtService));
                  Write-Host $inpUsernameAtService 'password from litepas.dat copied into clipboard.';
               }
            } else {
               Write-Host 'Extern file litepas.dat not exists.';
            }
         }

         ':help' {
            Write-Host $helpTextRus
         }
         

         ':lite' {
            [Windows.Forms.Clipboard]::SetText((
               GetPassword $masterPasswordSecure $inpUsernameAtService $salt) + $suffix);
            Write-Host $inpUsernameAtService 'password was copied into clipboard. Extern file wasn''t use.';
         }

         ':masterpassword' {
            if(Test-Path litepas.dat) {
               if(Test-Path variable:\dataStore) {Remove-Variable dataStore};
               $dataStore = Import-Clixml -path litepas.dat;
            } else {
               Write-Host 'Extern file litepas.dat not exists. Nothing to change.';
               Break;
            }
            $masterPasswordModSecure = Read-Host 'Enter password' -AsSecureString;
            $masterPasswordModSecureShadow = Read-Host 'Enter the same password' -AsSecureString;
            $masterPasswordMod = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($masterPasswordModSecure));

            if($masterPasswordMod -ne `
               [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [Runtime.InteropServices.Marshal]::SecureStringToBSTR(
                       $masterPasswordModSecureShadow))
            ){
               Write-Host 'The second password is differ.';
               Break;
            }

            $itWasFound = @();
            $dataStore.GetEnumerator() | ForEach-Object {$itWasFound += $_.Name};
            ForEach($i in $itWasFound) {
               $toSave = WriteXor (GetPassword $masterPasswordModSecure $i $salt) `
                  (ReadXor (GetPassword $masterPasswordSecure $i $salt) $dataStore.$i);
               $dataStore.Set_Item($i, $toSave);
            }
            Export-Clixml -path litepas.dat -inputObject $dataStore;
            Remove-Variable masterPasswordModSecureShadow
            Clear-Variable masterPasswordSecure;
            $masterPasswordSecure = $masterPasswordModSecure
            Write-Host 'New master-password was assigned.'
         }

         ':put' {
            if( -not ($inpUsernameAtService -match '^^[^^\x40]+[\x40][^^\x40]+$')) {
               $confirmation = Read-Host 'It''s recommended to store data in' `
                  'username@service format. Continue (type ''yes'')?';
               if($confirmation -ne 'yes') {Break;}
            }
            $userPasswordSecure = Read-Host 'Enter password' -AsSecureString;
            $userPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($userPasswordSecure));
            if($userPassword -eq '') {
               Add-Type -AssemblyName System.Web;
               $userPassword = [System.Web.Security.Membership]::GeneratePassword(26, 2);
               Write-Host 'Password generated.';
            } else {
               $userPasswordSecureShadow = Read-Host 'Enter the same password' -AsSecureString;
               if($userPassword -ne `
                  [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                       [Runtime.InteropServices.Marshal]::SecureStringToBSTR(
                          $userPasswordSecureShadow))
               ){
                  Write-Host 'The second password is differ.';
                  Break;
               }
            }
            if(Test-Path litepas.dat) {
               if(Test-Path variable:\dataStore) {Remove-Variable dataStore};
               $dataStore = Import-Clixml -path litepas.dat;
            } else {
               $dataStore = @{masterPassword = (
                  WriteXor (GetPassword $masterPasswordSecure 'masterPassword' $salt) 'masterPassword'
               )};
            }

            $toSave = WriteXor `
                         (GetPassword $masterPasswordSecure $inpUsernameAtService $salt) `
                         $userPassword;

            if($dataStore.ContainsKey($inpUsernameAtService)) {
               $confirmation =
                  Read-Host `
                     'ATTENTION! There is alredy exists' $inpUsernameAtService `
                     'in you litepas.dat. If you replace it now, there' `
                     'is no way to restore it. Do you want to replace it' `
                     '(type ''yes'' for replace)?';
            } else {
               $confirmation = 'yes'
            }

            if($confirmation -eq 'yes') {
               $dataStore.Set_Item($inpUsernameAtService, $toSave);
               Export-Clixml -path litepas.dat -inputObject $dataStore;
               Write-Host 'Password' $inpUsernameAtService 'saved successful.';
            } else {
               Write-Host 'Not saved.'
            }
         }

         ':quit' {
            $nextIneration = $False
         }

         Default {
            Write-Host 'Waiting command, type :help for user manual.'
         }
      }
   }
   Write-Host 'Bye...';
   Start-Sleep 3;
}
Main;
