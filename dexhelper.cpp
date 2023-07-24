#include "dexhelper.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

DexHelper::DexHelper()
{   
    mRawBuf = NULL;
}

DexHelper::~DexHelper()
{
    if(mRawBuf)
    {
        free(mRawBuf);
        mRawBuf = NULL;
    }
}

void DexHelper::PrintHeader()
{
    printf("\n=======================DexHeader=======================\n");
    printf("magic: ");
    for (size_t i = 0; i < sizeof(mDexHeader.magic_); i++)
    {
        printf("%02X ", mDexHeader.magic_[i]);
    }
    printf("\n");
    printf("checlsi:            0X%08X\n", mDexHeader.checksum_);
    printf("signature: ");
    for (size_t i = 0; i < sizeof(mDexHeader.signature_); i++)
    {
        printf("%02X ", mDexHeader.signature_[i]);
    }
    printf("\n");
    printf("file size:          0X%08X\n", mDexHeader.file_size_);
    printf("header size:        0X%08X\n", mDexHeader.header_size_); 
    printf("endian tag:         0X%08X\n", mDexHeader.endian_tag_);
    printf("link size:          0X%08X\n", mDexHeader.link_size_);
    printf("link offset:        0X%08X\n", mDexHeader.link_off_);
    printf("map off:            0X%08X\n", mDexHeader.map_off_); 
    printf("string ids size:    0X%08X\n", mDexHeader.string_ids_size_);
    printf("string ids offset:  0X%08X\n", mDexHeader.string_ids_off_);
    printf("type ids size:      0X%08X\n", mDexHeader.type_ids_size_);
    printf("type ids offset:    0X%08X\n", mDexHeader.type_ids_off_);
    printf("proto ids size:     0X%08X\n", mDexHeader.proto_ids_size_);
    printf("proto ids offset:   0X%08X\n", mDexHeader.proto_ids_off_);
    printf("field ids size:     0X%08X\n", mDexHeader.field_ids_size_);
    printf("field ids offset:   0X%08X\n", mDexHeader.field_ids_off_);
    printf("method ids size:    0X%08X\n", mDexHeader.method_ids_size_);
    printf("method ids offset:  0X%08X\n", mDexHeader.method_ids_off_);
    printf("class defs size:    0X%08X\n", mDexHeader.class_defs_size_);
    printf("class defs offset:  0X%08X\n", mDexHeader.class_defs_off_);
    printf("data size:          0X%08X\n", mDexHeader.data_size_);
    printf("data offset:        0X%08X\n", mDexHeader.data_off_);
}

void DexHelper::PrintStringIds()
{
    printf("\n=======================String=======================\n");
    for (size_t i = 0; i < mStringArr.size(); i++)
    {
        printf("[%d] offset: %d %s\n", (int32_t)i, mStringArr[i].str_id.string_data_off_, 
        mStringArr[i].str.c_str());
    }
    
}

void DexHelper::PrintType()
{
    printf("\n=======================Type=======================\n");
    for (size_t i = 0; i < mTypeArr.size(); i++)
    {
        printf("[%d] typeid: %d %s\n", 
            (int)i,
            (int)mTypeArr[i].type_id.descriptor_idx_,
            mTypeArr[i].type_str.c_str());
    }
}

void DexHelper::PrintField()
{
    printf("\n=======================Field=======================\n");

    for (size_t i = 0; i < mFieldArr.size(); i++)
    {
        printf("[%d] class: %s, type: %s, name: %s\n", (int )i, 
            mFieldArr[i].class_name.c_str(),
            mFieldArr[i].field_type.c_str(),
            mFieldArr[i].name.c_str());
    }
    
}

void DexHelper::PrintProto()
{
    printf("\n=======================Proto=======================\n");

    for (size_t i = 0; i < mProtoArr.size(); i++)
    {
        printf("[%d] shoty: %s, return: %s, params: ", (int)i, 
            mProtoArr[i].shorty_str.c_str(),
            mProtoArr[i].ret_str.c_str());

        if(mProtoArr[i].params.size())
        {
            for (size_t j = 0; j < mProtoArr[i].params.size(); j++)
            {
                printf("%s", mProtoArr[i].params[j].type_str.c_str());
            }
        }else
        {
            printf("null");
        }
        
        
        printf("\n");
    }
}

void DexHelper::PrintMethod()
{
    printf("\n=======================Method=======================\n");

    for (size_t i = 0; i < mMethodArr.size(); i++)
    {
        printf("[%d] class: %s, proto: %s, name: %s\n", (int)i,
            mMethodArr[i].class_name.c_str(),
            mMethodArr[i].proto.shorty_str.c_str(),
            mMethodArr[i].name.c_str());
    }
}

void DexHelper::PrintClass()
{
    printf("\n=======================Class=======================\n");

    for (size_t i = 0; i < mClassArr.size(); i++)
    {
        printf("[%d] class: %s-----------\n", (int)i, mClassArr[i].class_type.type_str.c_str());
        printf("access flag: 0x%08x\n", mClassArr[i].access_flag);
        printf("super lcass: %s\n", mClassArr[i].superclass_type.type_str.c_str()); 
        printf("interfaces: ");
        for (size_t j = 0; j < mClassArr[i].interfaces.size(); j++)
        {
            printf("%s", mClassArr[i].interfaces[j].type_str.c_str());  
        }
        printf("\nfile name: %s\n", mClassArr[i].file_name.c_str());
        printf("annotation off: 0x%08x\n", mClassArr[i].annotations);
        printf("static value: 0x%08x\n", mClassArr[i].static_value);

        printf("\nstatic field: \n");
        for (size_t k = 0; k < mClassArr[i].class_data.staticFieldsSize; k++)
        {
            printf("type: %s, name: %s access: %0x08x\n",
                mClassArr[i].class_data.staticFields[k].field.field_type.c_str(),
                mClassArr[i].class_data.staticFields[k].field.name.c_str(),
                mClassArr[i].class_data.staticFields[k].access_flag);
        }
        
        printf("\ninstance field: \n");
        for (size_t k = 0; k < mClassArr[i].class_data.instanceFieldsSize; k++)
        {
            printf("type: %s, name: %s access: %0x08x\n",
                mClassArr[i].class_data.instanceFields[k].field.field_type.c_str(),
                mClassArr[i].class_data.instanceFields[k].field.name.c_str(),
                mClassArr[i].class_data.instanceFields[k].access_flag);
        }

        printf("\ndirect method:\n");
        for (size_t k = 0; k < mClassArr[i].class_data.directMethodsSize; k++)
        {
            printf("[%d] ", (int)k);
            printf("proto: %s, name:%s, access: 0x%08x\n",
                 mClassArr[i].class_data.directMethods[k].method.proto.shorty_str.c_str(),
                 mClassArr[i].class_data.directMethods[k].method.name.c_str(),
                 mClassArr[i].class_data.directMethods[k].access_flag);

            printf("registers_size: %x, ins_size: %x, outs size: %x, tries size: %x, debug info off: %x, insns size: %x\n",
                mClassArr[i].class_data.directMethods[k].code.registers_size_,
                mClassArr[i].class_data.directMethods[k].code.ins_size_,
                mClassArr[i].class_data.directMethods[k].code.outs_size_,
                mClassArr[i].class_data.directMethods[k].code.tries_size_,
                mClassArr[i].class_data.directMethods[k].code.debug_info_off_,
                mClassArr[i].class_data.directMethods[k].code.insns_size_in_code_units_);

            printf("ins: ");
            for (size_t p = 0; p <  mClassArr[i].class_data.directMethods[k].code.insns_size_in_code_units_; p++)
            {
                printf("%04x ", mClassArr[i].class_data.directMethods[k].code.ins_arr[p] & 0xFF);
            }
            printf("\n");
        }
        
        printf("\nvirtual method:\n");
        for (size_t k = 0; k < mClassArr[i].class_data.virtualMethodsSize; k++)
        {
            printf("[%d] ", (int)k);
            printf("proto: %s, name:%s, access: 0x%08x\n",
                 mClassArr[i].class_data.virtualMethods[k].method.proto.shorty_str.c_str(),
                 mClassArr[i].class_data.virtualMethods[k].method.name.c_str(),
                 mClassArr[i].class_data.virtualMethods[k].access_flag);

            printf("registers_size: %x, ins_size: %x, outs size: %x, tries size: %x, debug info off: %x, insns size: %x\n",
                mClassArr[i].class_data.virtualMethods[k].code.registers_size_,
                mClassArr[i].class_data.virtualMethods[k].code.ins_size_,
                mClassArr[i].class_data.virtualMethods[k].code.outs_size_,
                mClassArr[i].class_data.virtualMethods[k].code.tries_size_,
                mClassArr[i].class_data.virtualMethods[k].code.debug_info_off_,
                mClassArr[i].class_data.virtualMethods[k].code.insns_size_in_code_units_);

            printf("ins: ");
            for (size_t p = 0; p <  mClassArr[i].class_data.virtualMethods[k].code.insns_size_in_code_units_; p++)
            {
                printf("%04x ", mClassArr[i].class_data.virtualMethods[k].code.ins_arr[p] & 0xFFFF);
            }
            printf("\n");
        }
        printf("\n");
    }
}

int DexHelper::Parse(char* buf, int size)
{
    mRawBuf = (char*)malloc(size);
    if(mRawBuf == NULL)
    {
        return -1;
    }

    memcpy(mRawBuf, buf, size);

    if(buf == NULL)
    {
        return -1;
    }

    if(memcmp(buf, "dex", strlen("dex"))!= 0)
    {
        return -2;
    }

    //Parse Header
    mDexHeader = *(Header*)buf;

    if(mDexHeader.file_size_ != size)
    {
        return -3;
    }
    
    PrintHeader();

    //Parse String Ids
    int* string_ids = (int*)(buf + mDexHeader.string_ids_off_);
    for (size_t i = 0; i < mDexHeader.string_ids_size_; i++, string_ids++)
    {
        //MUTF-8 string to char*
        StringIdEx stringid;
        stringid.str_id.string_data_off_ = *string_ids;
        stringid.str = GetMUTF8Data(*string_ids + buf);
        mStringArr.push_back(stringid);
    }
    PrintStringIds();

    //Parse Type Ids
    TypeId* typeids = (TypeId*)(mDexHeader.type_ids_off_ + buf);
    for (size_t i = 0; i < mDexHeader.type_ids_size_; i++)
    {
        Type type;
        type.type_id = typeids[i];
        type.type_str = mStringArr[typeids[i].descriptor_idx_].str;
        mTypeArr.push_back(type);
    }
    PrintType();

    //Parse Proto Ids
    ProtoId* proto_ids = (ProtoId*)(mDexHeader.proto_ids_off_ + buf);
    for (size_t i = 0; i < mDexHeader.proto_ids_size_; i++)
    {
        Proto proto;
        proto.proto_id = proto_ids[i];
        proto.shorty_str = mStringArr[proto_ids[i].shorty_idx_].str;
        proto.ret_str = mTypeArr[proto_ids[i].return_type_idx_].type_str;
        
        if(proto_ids[i].parameters_off_)
        {
            TypeList* param_list =  (TypeList* )(proto_ids[i].parameters_off_ + buf);

            for (size_t i = 0; i < param_list->size_; i++)
            {
                Type type;
                type.type_id.descriptor_idx_ = param_list->list_[i].type_idx_;
                type.type_str = mTypeArr[param_list->list_[i].type_idx_].type_str;
                proto.params.push_back(type);
            }
        }
        mProtoArr.push_back(proto);
    }
    PrintProto();

    //parse Field Ids
    FieldId* file_ids = (FieldId*)(mDexHeader.field_ids_off_ + buf);
    for (size_t i = 0; i < mDexHeader.field_ids_size_; i++)
    {
        Field field;
        field.field_id = file_ids[i];
        field.class_name = mTypeArr[file_ids[i].class_idx_].type_str;
        field.field_type = mTypeArr[file_ids[i].type_idx_].type_str;
        field.name = mStringArr[file_ids[i].name_idx_].str;
        mFieldArr.push_back(field);
    }
    PrintField();

    //Parse Method Ids
    MethodId* method_ids = (MethodId*)(mDexHeader.method_ids_off_ + buf);
    for (size_t i = 0; i < mDexHeader.method_ids_size_; i++)
    {
        Method method;
        method.method_id = method_ids[i];
        method.class_name = mTypeArr[method_ids[i].class_idx_].type_str; 
        method.name = mStringArr[method_ids[i].name_idx_].str;
        method.proto = mProtoArr[method_ids[i].proto_idx_];
        mMethodArr.push_back(method);
    }
    PrintMethod();

    //Parse Class Defs
    ClassDef* classdefs = (ClassDef*)(mDexHeader.class_defs_off_ + buf);
    for (size_t i = 0; i < mDexHeader.class_defs_size_; i++)
    {
        ClassDefEx class_defex = {0};
        class_defex.class_def = classdefs[i];
        class_defex.class_type = mTypeArr[ class_defex.class_def.class_idx_];
        class_defex.access_flag = class_defex.class_def.access_flags_;
        class_defex.superclass_type = mTypeArr[class_defex.class_def.superclass_idx_];
        class_defex.file_name = mStringArr[class_defex.class_def.source_file_idx_].str;
        class_defex.annotations = class_defex.class_def.annotations_off_;
        class_defex.static_value = class_defex.class_def.static_values_off_;

        if(class_defex.class_def.interfaces_off_)
        {
            TypeList* interface_list = (TypeList*)(class_defex.class_def.interfaces_off_ + buf);
            for (size_t j = 0; j < interface_list->size_; j++)
            {
                class_defex.interfaces.push_back(mTypeArr[ interface_list->list_[j].type_idx_]);
            }
        }
        
        //parse class data
        char* data = (char*)(class_defex.class_def.class_data_off_ + buf);
        DexClassData class_data;
        class_data.staticFieldsSize = readUnsignedLeb128(&data);
        class_data.instanceFieldsSize = readUnsignedLeb128(&data);
        class_data.directMethodsSize = readUnsignedLeb128(&data);
        class_data.virtualMethodsSize = readUnsignedLeb128(&data);
        
        int lastId = 0;
        for (size_t j = 0; j < class_data.staticFieldsSize; j++)
        {
            DexField dex_field = {0};
            lastId += readUnsignedLeb128(&data);
            dex_field.field = mFieldArr[lastId];
            dex_field.access_flag = readUnsignedLeb128(&data);
            class_data.staticFields.push_back(dex_field);
        }

        lastId = 0;
        for (size_t j = 0; j < class_data.instanceFieldsSize; j++)
        {
            DexField dex_field = {0};
            lastId += readUnsignedLeb128(&data);
            dex_field.field = mFieldArr[lastId];
            dex_field.access_flag = readUnsignedLeb128(&data);
            class_data.instanceFields.push_back(dex_field);
        }

        lastId = 0;
        for (size_t j = 0; j < class_data.directMethodsSize; j++)
        {
            DexMethod dex_method= {0};
            lastId += readUnsignedLeb128(&data);
            dex_method.method = mMethodArr[lastId];
            dex_method.access_flag = readUnsignedLeb128(&data);
            CodeItem* code = (CodeItem*)(readUnsignedLeb128(&data) + buf);
            dex_method.code.registers_size_ = code->registers_size_;
            dex_method.code.ins_size_ = code->ins_size_;
            dex_method.code.outs_size_ = code->outs_size_;
            dex_method.code.debug_info_off_ = code->debug_info_off_;
            dex_method.code.insns_size_in_code_units_ = code->insns_size_in_code_units_;

            ushort* ins = code->insns_;
            for (size_t k = 0; k < code->insns_size_in_code_units_; k++)
            {
                dex_method.code.ins_arr.push_back(ins[k]);
            }

            class_data.directMethods.push_back(dex_method);
        }
        
        lastId = 0;
        for (size_t j = 0; j < class_data.virtualMethodsSize; j++)
        {
            DexMethod dex_method = {0};
            lastId += readUnsignedLeb128(&data);
            dex_method.method = mMethodArr[lastId];
            dex_method.access_flag = readUnsignedLeb128(&data);
            CodeItem* code = (CodeItem*)(readUnsignedLeb128(&data) + buf);
            dex_method.code.registers_size_ = code->registers_size_;
            dex_method.code.ins_size_ = code->ins_size_;
            dex_method.code.outs_size_ = code->outs_size_;
            dex_method.code.debug_info_off_ = code->debug_info_off_;
            dex_method.code.insns_size_in_code_units_ = code->insns_size_in_code_units_;

            ushort* ins = code->insns_;
            for (size_t k = 0; k < code->insns_size_in_code_units_; k++)
            {
                dex_method.code.ins_arr.push_back(ins[k]);
            }

            class_data.virtualMethods.push_back(dex_method);
        }

        class_defex.class_data = class_data;
        mClassArr.push_back(class_defex);
    }
    PrintClass();

    return 0;
}

int DexHelper::readUnsignedLeb128(char** pStream) {
    char* ptr = *pStream;
    unsigned int result = *(ptr++);
    if (result > 0x7f) {
        unsigned int cur = *(ptr++);
        result = (result & 0x7f) | ((cur & 0x7f) << 7);
        if (cur > 0x7f) {
            cur = *(ptr++);
            result |= (cur & 0x7f) << 14;
            if (cur > 0x7f) {
                cur = *(ptr++);
                result |= (cur & 0x7f) << 21;
                if (cur > 0x7f) {
                    cur = *(ptr++);
                    result |= cur << 28;
                }
            }
        }
    }
    *pStream = ptr;
    return result;
}

char* DexHelper::GetMUTF8Data(char* mutf8_str)
{
    while(*(mutf8_str++)>0x7F);
    return mutf8_str;
}