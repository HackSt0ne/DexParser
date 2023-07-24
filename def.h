#include <stdint.h>
#include <stddef.h>
#include <string>
#include <vector>

static const size_t kSha1DigestSize = 20;

// Raw header_item.
struct Header
{
    uint8_t magic_[8];
    uint32_t checksum_; // See also location_checksum_
    uint8_t signature_[kSha1DigestSize];
    uint32_t file_size_;   // size of entire file
    uint32_t header_size_; // offset to start of next section
    uint32_t endian_tag_;
    uint32_t link_size_;       // unused
    uint32_t link_off_;        // unused
    uint32_t map_off_;         // unused
    uint32_t string_ids_size_; // number of StringIds
    uint32_t string_ids_off_;  // file offset of StringIds array
    uint32_t type_ids_size_;   // number of TypeIds, we don't support more than 65535
    uint32_t type_ids_off_;    // file offset of TypeIds array
    uint32_t proto_ids_size_;  // number of ProtoIds, we don't support more than 65535
    uint32_t proto_ids_off_;   // file offset of ProtoIds array
    uint32_t field_ids_size_;  // number of FieldIds
    uint32_t field_ids_off_;   // file offset of FieldIds array
    uint32_t method_ids_size_; // number of MethodIds
    uint32_t method_ids_off_;  // file offset of MethodIds array
    uint32_t class_defs_size_; // number of ClassDefs
    uint32_t class_defs_off_;  // file offset of ClassDef array
    uint32_t data_size_;       // unused
    uint32_t data_off_;        // unused
};

// Map item type codes.
enum
{
    kDexTypeHeaderItem = 0x0000,
    kDexTypeStringIdItem = 0x0001,
    kDexTypeTypeIdItem = 0x0002,
    kDexTypeProtoIdItem = 0x0003,
    kDexTypeFieldIdItem = 0x0004,
    kDexTypeMethodIdItem = 0x0005,
    kDexTypeClassDefItem = 0x0006,
    kDexTypeMapList = 0x1000,
    kDexTypeTypeList = 0x1001,
    kDexTypeAnnotationSetRefList = 0x1002,
    kDexTypeAnnotationSetItem = 0x1003,
    kDexTypeClassDataItem = 0x2000,
    kDexTypeCodeItem = 0x2001,
    kDexTypeStringDataItem = 0x2002,
    kDexTypeDebugInfoItem = 0x2003,
    kDexTypeAnnotationItem = 0x2004,
    kDexTypeEncodedArrayItem = 0x2005,
    kDexTypeAnnotationsDirectoryItem = 0x2006,
};

// Raw string_id_item.
struct StringId
{
    uint32_t string_data_off_; // offset in bytes from the base address
};

struct StringIdEx
{
    StringId str_id;
    std::string str;
};

// Raw type_id_item.
struct TypeId
{
    uint32_t descriptor_idx_; // index into string_ids
};

struct Type
{
    TypeId type_id;
    std::string type_str;
};

// Raw proto_id_item.
struct ProtoId
{
    uint32_t shorty_idx_;      // index into string_ids array for shorty descriptor
    uint16_t return_type_idx_; // index into type_ids array for return type
    uint16_t pad_;             // padding = 0
    uint32_t parameters_off_;  // file offset to type_list for parameter types
};

// Raw type_item.
struct TypeItem
{
    uint16_t type_idx_; // index into type_ids section
};

struct TypeList
{
    uint32_t size_;    // size of the list, in entries
    TypeItem list_[1]; // type list
};

struct Proto
{
    ProtoId proto_id;
    std::string shorty_str;
    std::string ret_str;
    std::vector<Type> params;
};

// Raw field_id_item.
struct FieldId
{
    uint16_t class_idx_; // index into type_ids_ array for defining class
    uint16_t type_idx_;  // index into type_ids_ array for field type
    uint32_t name_idx_;  // index into string_ids_ array for field name
};

struct Field
{
    FieldId field_id;
    std::string class_name; // class name string
    std::string field_type; // field type string
    std::string name;       // name string
};

// Raw method_id_item.
struct MethodId
{
    uint16_t class_idx_; // index into type_ids_ array for defining class
    uint16_t proto_idx_; // index into proto_ids_ array for method prototype
    uint32_t name_idx_;  // index into string_ids_ array for method name
};

struct Method
{
    MethodId method_id;
    std::string class_name; // class name string
    Proto proto;        // method proto
    std::string name;       // name
};

// Raw class_def_item.
struct ClassDef
{
    uint16_t class_idx_; // index into type_ids_ array for this class
    uint16_t pad1_;      // padding = 0
    uint32_t access_flags_;
    uint16_t superclass_idx_;    // index into type_ids_ array for superclass
    uint16_t pad2_;              // padding = 0
    uint32_t interfaces_off_;    // file offset to TypeList
    uint32_t source_file_idx_;   // index into string_ids_ for source file name
    uint32_t annotations_off_;   // file offset to annotations_directory_item
    uint32_t class_data_off_;    // file offset to class_data_item
    uint32_t static_values_off_; // file offset to EncodedArray
};

struct DexField
{
    Field field;
    int access_flag;
};

// Raw code_item.
struct CodeItem
{
    uint16_t registers_size_;           // the number of registers used by this code
                                        //   (locals + parameters)
    uint16_t ins_size_;                 // the number of words of incoming arguments to the method
                                        //   that this code is for
    uint16_t outs_size_;                // the number of words of outgoing argument space required
                                        //   by this code for method invocation
    uint16_t tries_size_;               // the number of try_items for this instance. If non-zero,
                                        //   then these appear as the tries array just after the
                                        //   insns in this instance.
    uint32_t debug_info_off_;           // file offset to debug info stream
    uint32_t insns_size_in_code_units_; // size of the insns array, in 2 byte code units
    uint16_t insns_[1];                 // actual array of bytecode.
};

struct CodeItemEx
{
    uint16_t registers_size_;              
    uint16_t ins_size_;                  
    uint16_t outs_size_;                 
    uint16_t tries_size_;                
    uint32_t debug_info_off_;           
    uint32_t insns_size_in_code_units_; 
    std::vector<uint16_t> ins_arr;
};

struct DexMethod
{
    Method method;
    int access_flag;
    CodeItemEx code;
};

struct DexClassData
{
    int staticFieldsSize;
    int instanceFieldsSize;
    int directMethodsSize;
    int virtualMethodsSize;
    
    std::vector<DexField> staticFields;
    std::vector<DexField> instanceFields;
    std::vector<DexMethod> directMethods;
    std::vector<DexMethod> virtualMethods;
};

struct ClassDefEx
{
    ClassDef class_def;
    Type class_type;
    int access_flag;
    Type superclass_type;
    std::vector<Type> interfaces;
    std::string file_name;
    int annotations;      //
    DexClassData class_data;
    int static_value;     //
};