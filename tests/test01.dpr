program test01;

{$APPTYPE CONSOLE}

uses
  SysUtils,
  Classes,
  windows,
  SeAES256 in '..\SeCrypt\SeAES256.pas',
  SeBase64 in '..\SeCrypt\SeBase64.pas',
  SeSHA256 in '..\SeCrypt\SeSHA256.pas',
  SeStreams in '..\SeCrypt\SeStreams.pas';

function TestAESVector(Key, PlainText, CipherText: AnsiString): Boolean;
var
  AESKey: TAESKey;
  ExpandedKey: TAESExpandedKey;
  State: TAESState;
begin
  AESCopyKey(AESKey,PAnsiChar(Key));
  AESExpandKey(ExpandedKey,AESKey);
  move(PAnsiChar(PlainText)^,State,Sizeof(State));
  AESEncrypt(State,ExpandedKey);
  Result:= StrLComp(PAnsiChar(@State),PAnsiChar(CipherText),Sizeof(State)) = 0;
end;

function TestBase64Vector(InData, OutData: AnsiString): Boolean;
begin
  Result:= BinToStr(PByteArray(PAnsiChar(InData)),Length(InData))=OutData
end;

var
  i,j: Integer;
  b: Byte;
  Datos: TMemoryStream;
  Cifr: TMemoryStream;
  Desc: TMemoryStream;
  Key: TAESKey;
  AEnc: TAESEnc;
  ADec: TAESDec;
  BEnc: TBase64Enc;
  BDec: TBase64Dec;
begin
  Randomize;
  Writeln;
  Writeln('=== SeCrypt Test ===');
  Writeln;
  Writeln('Comprobando AES256 ...');
  Writeln('Vector 1: ' + BoolToStr(( TestAESVector(
    #$60#$3d#$eb#$10#$15#$ca#$71#$be#$2b#$73#$ae#$f0#$85#$7d#$77#$81 +
    #$1f#$35#$2c#$07#$3b#$61#$08#$d7#$2d#$98#$10#$a3#$09#$14#$df#$f4,
    #$6b#$c1#$be#$e2#$2e#$40#$9f#$96#$e9#$3d#$7e#$11#$73#$93#$17#$2a,
    #$f3#$ee#$d1#$bd#$b5#$d2#$a0#$3c#$06#$4b#$5a#$7e#$3d#$b1#$81#$f8)),TRUE));
  Writeln('Vector 2: ' + BoolToStr(( TestAESVector(
    #$60#$3d#$eb#$10#$15#$ca#$71#$be#$2b#$73#$ae#$f0#$85#$7d#$77#$81 +
    #$1f#$35#$2c#$07#$3b#$61#$08#$d7#$2d#$98#$10#$a3#$09#$14#$df#$f4,
    #$ae#$2d#$8a#$57#$1e#$03#$ac#$9c#$9e#$b7#$6f#$ac#$45#$af#$8e#$51,
    #$59#$1c#$cb#$10#$d4#$10#$ed#$26#$dc#$5b#$a7#$4a#$31#$36#$28#$70)),TRUE));
  Writeln('Vector 3: ' + BoolToStr(( TestAESVector(
    #$60#$3d#$eb#$10#$15#$ca#$71#$be#$2b#$73#$ae#$f0#$85#$7d#$77#$81 +
    #$1f#$35#$2c#$07#$3b#$61#$08#$d7#$2d#$98#$10#$a3#$09#$14#$df#$f4,
    #$30#$c8#$1c#$46#$a3#$5c#$e4#$11#$e5#$fb#$c1#$19#$1a#$0a#$52#$ef,
    #$b6#$ed#$21#$b9#$9c#$a6#$f4#$f9#$f1#$53#$e7#$b1#$be#$af#$ed#$1d)),TRUE));
  Writeln('Vector 4: ' + BoolToStr(( TestAESVector(
    #$60#$3d#$eb#$10#$15#$ca#$71#$be#$2b#$73#$ae#$f0#$85#$7d#$77#$81 +
    #$1f#$35#$2c#$07#$3b#$61#$08#$d7#$2d#$98#$10#$a3#$09#$14#$df#$f4,
    #$f6#$9f#$24#$45#$df#$4f#$9b#$17#$ad#$2b#$41#$7b#$e6#$6c#$37#$10,
    #$23#$30#$4b#$7a#$39#$f9#$f3#$ff#$06#$7d#$8d#$8f#$9e#$24#$ec#$c7)),TRUE));
  Writeln;
  Writeln('Comprobando SHA256 ...');
  Writeln('Vector 1: ' + BoolToStr((
    (LowerCase(SHA256ToStr(CalcSHA256('')))
      = 'e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855')),TRUE));
  Writeln('Vector 2: ' + BoolToStr((
    (LowerCase(SHA256ToStr(CalcSHA256('abc')))
      = 'ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad')),TRUE));
  Writeln('Vector 3: ' + BoolToStr((
    (LowerCase(SHA256ToStr(CalcSHA256('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')))
      = '248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1')),TRUE));
  Writeln('Vector 4: ' + BoolToStr((
    (LowerCase(SHA256ToStr(CalcSHA256('The quick brown fox jumps over the lazy dog')))
      = 'd7a8fbb3 07d78094 69ca9abc b0082e4f 8d5651e4 6d3cdb76 2d02d0bf 37c9e592')),TRUE));
  Writeln('Vector 5: ' + BoolToStr((
    (LowerCase(SHA256ToStr(CalcSHA256(StringOfChar('a',1000000))))
      = 'cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0')),TRUE));
  Writeln;
  Writeln('Comprobando BASE64 ...');
  Writeln('Vector 1: ' + BoolToStr(TestBase64Vector('',''),TRUE));
  Writeln('Vector 2: ' + BoolToStr(TestBase64Vector('f','Zg=='),TRUE));
  Writeln('Vector 3: ' + BoolToStr(TestBase64Vector('fo','Zm8='),TRUE));
  Writeln('Vector 4: ' + BoolToStr(TestBase64Vector('foo','Zm9v'),TRUE));
  Writeln('Vector 5: ' + BoolToStr(TestBase64Vector('foob','Zm9vYg=='),TRUE));
  Writeln('Vector 6: ' + BoolToStr(TestBase64Vector('fooba','Zm9vYmE='),TRUE));
  Writeln('Vector 7: ' + BoolToStr(TestBase64Vector('foobar','Zm9vYmFy'),TRUE));
  Writeln;
  Writeln('Probando datos aleatorios ...');
  Datos:= TMemoryStream.Create;
  Cifr:= TMemoryStream.Create;
  Desc:= TMemoryStream.Create;
  try
    // Repetimos el test para distintos tamaños de buffer
    for i:= 0 to 15 do
    begin
      Datos.Clear;
      Cifr.Clear;
      Desc.Clear;
      // Llenamos un buffer con numeros aleatorios
      for j:= 1 to (4*1024) + i do
      begin
        b:= Random(256);
        Datos.WriteBuffer(b,1);
      end;
      // Generamos una clave aleatoria
      for j:= 0 to 7 do
        Key[j]:= Random(MAXINT);
      Write(Format('%d bytes: ',[Datos.Size]));
      // Ciframos usando AES y Base64
      BEnc:= TBase64Enc.Create(Cifr);
      AEnc:= TAESEnc.Create(BEnc,Key);
      try
        AEnc.CopyFrom(Datos,0);
      finally
        AEnc.Free;
        BEnc.Free;
      end;
      // Desciframos usando Base64 y AES
      ADec:= TAESDec.Create(Desc,Key);
      BDec:= TBase64Dec.Create(ADec);
      try
        BDec.CopyFrom(Cifr,0);
      finally
        BDec.Free;
        ADec.Free;
      end;
      // Comparamos los datos originales con los descifrados
      Writeln(BoolToStr((Datos.Size <= Desc.Size) and
        CompareMem(Datos.Memory,Desc.Memory,Datos.Size), TRUE));
    end;
  finally
    Datos.Free;
    Cifr.Free;
    Desc.Free;
  end;
  Readln;
end.
