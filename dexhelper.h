#include "def.h"
#include <vector>
#include <string>

class DexHelper
{
public:
    DexHelper();
    ~DexHelper();

    int Parse(char* buf, int size);

    void PrintHeader();
    void PrintStringIds();
    void PrintType();
    void PrintProto();
    void PrintField();
    void PrintMethod();
    void PrintClass();

private:
    int readUnsignedLeb128(char** pStream);
    char* GetMUTF8Data(char*);
private:
    Header mDexHeader; //dex header
    std::vector<StringIdEx> mStringArr; 
    std::vector<Type> mTypeArr; 
    std::vector<Proto> mProtoArr; 
    std::vector<Field> mFieldArr; 
    std::vector<Method> mMethodArr; 
    std::vector<ClassDefEx> mClassArr;
    char* mRawBuf;
};