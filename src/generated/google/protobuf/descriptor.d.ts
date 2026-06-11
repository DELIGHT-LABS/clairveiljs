import { BinaryReader, BinaryWriter } from "../../binary.js";
import { DeepPartial } from "../../helpers.js";
export declare enum FieldDescriptorProto_Type {
    TYPE_DOUBLE = 1,
    TYPE_FLOAT = 2,
    TYPE_INT64 = 3,
    TYPE_UINT64 = 4,
    TYPE_INT32 = 5,
    TYPE_FIXED64 = 6,
    TYPE_FIXED32 = 7,
    TYPE_BOOL = 8,
    TYPE_STRING = 9,
    TYPE_GROUP = 10,
    TYPE_MESSAGE = 11,
    TYPE_BYTES = 12,
    TYPE_UINT32 = 13,
    TYPE_ENUM = 14,
    TYPE_SFIXED32 = 15,
    TYPE_SFIXED64 = 16,
    TYPE_SINT32 = 17,
    TYPE_SINT64 = 18,
    UNRECOGNIZED = -1
}
export declare function fieldDescriptorProto_TypeFromJSON(object: any): FieldDescriptorProto_Type;
export declare function fieldDescriptorProto_TypeToJSON(object: FieldDescriptorProto_Type): string;
export declare enum FieldDescriptorProto_Label {
    LABEL_OPTIONAL = 1,
    LABEL_REQUIRED = 2,
    LABEL_REPEATED = 3,
    UNRECOGNIZED = -1
}
export declare function fieldDescriptorProto_LabelFromJSON(object: any): FieldDescriptorProto_Label;
export declare function fieldDescriptorProto_LabelToJSON(object: FieldDescriptorProto_Label): string;
export declare enum FileOptions_OptimizeMode {
    SPEED = 1,
    CODE_SIZE = 2,
    LITE_RUNTIME = 3,
    UNRECOGNIZED = -1
}
export declare function fileOptions_OptimizeModeFromJSON(object: any): FileOptions_OptimizeMode;
export declare function fileOptions_OptimizeModeToJSON(object: FileOptions_OptimizeMode): string;
export declare enum FieldOptions_CType {
    STRING = 0,
    CORD = 1,
    STRING_PIECE = 2,
    UNRECOGNIZED = -1
}
export declare function fieldOptions_CTypeFromJSON(object: any): FieldOptions_CType;
export declare function fieldOptions_CTypeToJSON(object: FieldOptions_CType): string;
export declare enum FieldOptions_JSType {
    JS_NORMAL = 0,
    JS_STRING = 1,
    JS_NUMBER = 2,
    UNRECOGNIZED = -1
}
export declare function fieldOptions_JSTypeFromJSON(object: any): FieldOptions_JSType;
export declare function fieldOptions_JSTypeToJSON(object: FieldOptions_JSType): string;
/**
 * @name FileDescriptorSet
 * @package google.protobuf
 * @see proto type: google.protobuf.FileDescriptorSet
 */
export interface FileDescriptorSet {
    file: FileDescriptorProto[];
}
/**
 * @name FileDescriptorProto
 * @package google.protobuf
 * @see proto type: google.protobuf.FileDescriptorProto
 */
export interface FileDescriptorProto {
    name: string;
    package: string;
    dependency: string[];
    publicDependency: number[];
    weakDependency: number[];
    messageType: DescriptorProto[];
    enumType: EnumDescriptorProto[];
    service: ServiceDescriptorProto[];
    extension: FieldDescriptorProto[];
    options?: FileOptions;
    sourceCodeInfo?: SourceCodeInfo;
    syntax: string;
}
/**
 * @name DescriptorProto
 * @package google.protobuf
 * @see proto type: google.protobuf.DescriptorProto
 */
export interface DescriptorProto {
    name: string;
    field: FieldDescriptorProto[];
    extension: FieldDescriptorProto[];
    nestedType: DescriptorProto[];
    enumType: EnumDescriptorProto[];
    extensionRange: DescriptorProto_ExtensionRange[];
    oneofDecl: OneofDescriptorProto[];
    options?: MessageOptions;
    reservedRange: DescriptorProto_ReservedRange[];
    reservedName: string[];
}
/**
 * @name DescriptorProto_ExtensionRange
 * @package google.protobuf
 * @see proto type: google.protobuf.ExtensionRange
 */
export interface DescriptorProto_ExtensionRange {
    start: number;
    end: number;
}
/**
 * @name DescriptorProto_ReservedRange
 * @package google.protobuf
 * @see proto type: google.protobuf.ReservedRange
 */
export interface DescriptorProto_ReservedRange {
    start: number;
    end: number;
}
/**
 * @name FieldDescriptorProto
 * @package google.protobuf
 * @see proto type: google.protobuf.FieldDescriptorProto
 */
export interface FieldDescriptorProto {
    name: string;
    number: number;
    label: FieldDescriptorProto_Label;
    type: FieldDescriptorProto_Type;
    typeName: string;
    extendee: string;
    defaultValue: string;
    oneofIndex: number;
    jsonName: string;
    options?: FieldOptions;
}
/**
 * @name OneofDescriptorProto
 * @package google.protobuf
 * @see proto type: google.protobuf.OneofDescriptorProto
 */
export interface OneofDescriptorProto {
    name: string;
    options?: OneofOptions;
}
/**
 * @name EnumDescriptorProto
 * @package google.protobuf
 * @see proto type: google.protobuf.EnumDescriptorProto
 */
export interface EnumDescriptorProto {
    name: string;
    value: EnumValueDescriptorProto[];
    options?: EnumOptions;
}
/**
 * @name EnumValueDescriptorProto
 * @package google.protobuf
 * @see proto type: google.protobuf.EnumValueDescriptorProto
 */
export interface EnumValueDescriptorProto {
    name: string;
    number: number;
    options?: EnumValueOptions;
}
/**
 * @name ServiceDescriptorProto
 * @package google.protobuf
 * @see proto type: google.protobuf.ServiceDescriptorProto
 */
export interface ServiceDescriptorProto {
    name: string;
    method: MethodDescriptorProto[];
    options?: ServiceOptions;
}
/**
 * @name MethodDescriptorProto
 * @package google.protobuf
 * @see proto type: google.protobuf.MethodDescriptorProto
 */
export interface MethodDescriptorProto {
    name: string;
    inputType: string;
    outputType: string;
    options?: MethodOptions;
    clientStreaming: boolean;
    serverStreaming: boolean;
}
/**
 * @name FileOptions
 * @package google.protobuf
 * @see proto type: google.protobuf.FileOptions
 */
export interface FileOptions {
    javaPackage: string;
    javaOuterClassname: string;
    javaMultipleFiles: boolean;
    /**
     * @deprecated
     */
    javaGenerateEqualsAndHash: boolean;
    javaStringCheckUtf8: boolean;
    optimizeFor: FileOptions_OptimizeMode;
    goPackage: string;
    ccGenericServices: boolean;
    javaGenericServices: boolean;
    pyGenericServices: boolean;
    deprecated: boolean;
    ccEnableArenas: boolean;
    objcClassPrefix: string;
    csharpNamespace: string;
    uninterpretedOption: UninterpretedOption[];
}
/**
 * @name MessageOptions
 * @package google.protobuf
 * @see proto type: google.protobuf.MessageOptions
 */
export interface MessageOptions {
    messageSetWireFormat: boolean;
    noStandardDescriptorAccessor: boolean;
    deprecated: boolean;
    mapEntry: boolean;
    uninterpretedOption: UninterpretedOption[];
}
/**
 * @name FieldOptions
 * @package google.protobuf
 * @see proto type: google.protobuf.FieldOptions
 */
export interface FieldOptions {
    ctype: FieldOptions_CType;
    packed: boolean;
    jstype: FieldOptions_JSType;
    lazy: boolean;
    deprecated: boolean;
    weak: boolean;
    uninterpretedOption: UninterpretedOption[];
}
/**
 * @name OneofOptions
 * @package google.protobuf
 * @see proto type: google.protobuf.OneofOptions
 */
export interface OneofOptions {
    uninterpretedOption: UninterpretedOption[];
}
/**
 * @name EnumOptions
 * @package google.protobuf
 * @see proto type: google.protobuf.EnumOptions
 */
export interface EnumOptions {
    allowAlias: boolean;
    deprecated: boolean;
    uninterpretedOption: UninterpretedOption[];
}
/**
 * @name EnumValueOptions
 * @package google.protobuf
 * @see proto type: google.protobuf.EnumValueOptions
 */
export interface EnumValueOptions {
    deprecated: boolean;
    uninterpretedOption: UninterpretedOption[];
}
/**
 * @name ServiceOptions
 * @package google.protobuf
 * @see proto type: google.protobuf.ServiceOptions
 */
export interface ServiceOptions {
    deprecated: boolean;
    uninterpretedOption: UninterpretedOption[];
}
/**
 * @name MethodOptions
 * @package google.protobuf
 * @see proto type: google.protobuf.MethodOptions
 */
export interface MethodOptions {
    deprecated: boolean;
    uninterpretedOption: UninterpretedOption[];
}
/**
 * @name UninterpretedOption
 * @package google.protobuf
 * @see proto type: google.protobuf.UninterpretedOption
 */
export interface UninterpretedOption {
    name: UninterpretedOption_NamePart[];
    identifierValue: string;
    positiveIntValue: bigint;
    negativeIntValue: bigint;
    doubleValue: number;
    stringValue: Uint8Array;
    aggregateValue: string;
}
/**
 * @name UninterpretedOption_NamePart
 * @package google.protobuf
 * @see proto type: google.protobuf.NamePart
 */
export interface UninterpretedOption_NamePart {
    namePart: string;
    isExtension: boolean;
}
/**
 * @name SourceCodeInfo
 * @package google.protobuf
 * @see proto type: google.protobuf.SourceCodeInfo
 */
export interface SourceCodeInfo {
    location: SourceCodeInfo_Location[];
}
/**
 * @name SourceCodeInfo_Location
 * @package google.protobuf
 * @see proto type: google.protobuf.Location
 */
export interface SourceCodeInfo_Location {
    path: number[];
    span: number[];
    leadingComments: string;
    trailingComments: string;
    leadingDetachedComments: string[];
}
/**
 * @name GeneratedCodeInfo
 * @package google.protobuf
 * @see proto type: google.protobuf.GeneratedCodeInfo
 */
export interface GeneratedCodeInfo {
    annotation: GeneratedCodeInfo_Annotation[];
}
/**
 * @name GeneratedCodeInfo_Annotation
 * @package google.protobuf
 * @see proto type: google.protobuf.Annotation
 */
export interface GeneratedCodeInfo_Annotation {
    path: number[];
    sourceFile: string;
    begin: number;
    end: number;
}
/**
 * @name FileDescriptorSet
 * @package google.protobuf
 * @see proto type: google.protobuf.FileDescriptorSet
 */
export declare const FileDescriptorSet: {
    typeUrl: string;
    encode(message: FileDescriptorSet, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): FileDescriptorSet;
    fromPartial(object: DeepPartial<FileDescriptorSet>): FileDescriptorSet;
};
/**
 * @name FileDescriptorProto
 * @package google.protobuf
 * @see proto type: google.protobuf.FileDescriptorProto
 */
export declare const FileDescriptorProto: {
    typeUrl: string;
    encode(message: FileDescriptorProto, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): FileDescriptorProto;
    fromPartial(object: DeepPartial<FileDescriptorProto>): FileDescriptorProto;
};
/**
 * @name DescriptorProto
 * @package google.protobuf
 * @see proto type: google.protobuf.DescriptorProto
 */
export declare const DescriptorProto: {
    typeUrl: string;
    encode(message: DescriptorProto, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): DescriptorProto;
    fromPartial(object: DeepPartial<DescriptorProto>): DescriptorProto;
};
/**
 * @name DescriptorProto_ExtensionRange
 * @package google.protobuf
 * @see proto type: google.protobuf.ExtensionRange
 */
export declare const DescriptorProto_ExtensionRange: {
    typeUrl: string;
    encode(message: DescriptorProto_ExtensionRange, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): DescriptorProto_ExtensionRange;
    fromPartial(object: DeepPartial<DescriptorProto_ExtensionRange>): DescriptorProto_ExtensionRange;
};
/**
 * @name DescriptorProto_ReservedRange
 * @package google.protobuf
 * @see proto type: google.protobuf.ReservedRange
 */
export declare const DescriptorProto_ReservedRange: {
    typeUrl: string;
    encode(message: DescriptorProto_ReservedRange, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): DescriptorProto_ReservedRange;
    fromPartial(object: DeepPartial<DescriptorProto_ReservedRange>): DescriptorProto_ReservedRange;
};
/**
 * @name FieldDescriptorProto
 * @package google.protobuf
 * @see proto type: google.protobuf.FieldDescriptorProto
 */
export declare const FieldDescriptorProto: {
    typeUrl: string;
    encode(message: FieldDescriptorProto, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): FieldDescriptorProto;
    fromPartial(object: DeepPartial<FieldDescriptorProto>): FieldDescriptorProto;
};
/**
 * @name OneofDescriptorProto
 * @package google.protobuf
 * @see proto type: google.protobuf.OneofDescriptorProto
 */
export declare const OneofDescriptorProto: {
    typeUrl: string;
    encode(message: OneofDescriptorProto, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): OneofDescriptorProto;
    fromPartial(object: DeepPartial<OneofDescriptorProto>): OneofDescriptorProto;
};
/**
 * @name EnumDescriptorProto
 * @package google.protobuf
 * @see proto type: google.protobuf.EnumDescriptorProto
 */
export declare const EnumDescriptorProto: {
    typeUrl: string;
    encode(message: EnumDescriptorProto, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): EnumDescriptorProto;
    fromPartial(object: DeepPartial<EnumDescriptorProto>): EnumDescriptorProto;
};
/**
 * @name EnumValueDescriptorProto
 * @package google.protobuf
 * @see proto type: google.protobuf.EnumValueDescriptorProto
 */
export declare const EnumValueDescriptorProto: {
    typeUrl: string;
    encode(message: EnumValueDescriptorProto, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): EnumValueDescriptorProto;
    fromPartial(object: DeepPartial<EnumValueDescriptorProto>): EnumValueDescriptorProto;
};
/**
 * @name ServiceDescriptorProto
 * @package google.protobuf
 * @see proto type: google.protobuf.ServiceDescriptorProto
 */
export declare const ServiceDescriptorProto: {
    typeUrl: string;
    encode(message: ServiceDescriptorProto, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): ServiceDescriptorProto;
    fromPartial(object: DeepPartial<ServiceDescriptorProto>): ServiceDescriptorProto;
};
/**
 * @name MethodDescriptorProto
 * @package google.protobuf
 * @see proto type: google.protobuf.MethodDescriptorProto
 */
export declare const MethodDescriptorProto: {
    typeUrl: string;
    encode(message: MethodDescriptorProto, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): MethodDescriptorProto;
    fromPartial(object: DeepPartial<MethodDescriptorProto>): MethodDescriptorProto;
};
/**
 * @name FileOptions
 * @package google.protobuf
 * @see proto type: google.protobuf.FileOptions
 */
export declare const FileOptions: {
    typeUrl: string;
    encode(message: FileOptions, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): FileOptions;
    fromPartial(object: DeepPartial<FileOptions>): FileOptions;
};
/**
 * @name MessageOptions
 * @package google.protobuf
 * @see proto type: google.protobuf.MessageOptions
 */
export declare const MessageOptions: {
    typeUrl: string;
    encode(message: MessageOptions, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): MessageOptions;
    fromPartial(object: DeepPartial<MessageOptions>): MessageOptions;
};
/**
 * @name FieldOptions
 * @package google.protobuf
 * @see proto type: google.protobuf.FieldOptions
 */
export declare const FieldOptions: {
    typeUrl: string;
    encode(message: FieldOptions, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): FieldOptions;
    fromPartial(object: DeepPartial<FieldOptions>): FieldOptions;
};
/**
 * @name OneofOptions
 * @package google.protobuf
 * @see proto type: google.protobuf.OneofOptions
 */
export declare const OneofOptions: {
    typeUrl: string;
    encode(message: OneofOptions, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): OneofOptions;
    fromPartial(object: DeepPartial<OneofOptions>): OneofOptions;
};
/**
 * @name EnumOptions
 * @package google.protobuf
 * @see proto type: google.protobuf.EnumOptions
 */
export declare const EnumOptions: {
    typeUrl: string;
    encode(message: EnumOptions, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): EnumOptions;
    fromPartial(object: DeepPartial<EnumOptions>): EnumOptions;
};
/**
 * @name EnumValueOptions
 * @package google.protobuf
 * @see proto type: google.protobuf.EnumValueOptions
 */
export declare const EnumValueOptions: {
    typeUrl: string;
    encode(message: EnumValueOptions, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): EnumValueOptions;
    fromPartial(object: DeepPartial<EnumValueOptions>): EnumValueOptions;
};
/**
 * @name ServiceOptions
 * @package google.protobuf
 * @see proto type: google.protobuf.ServiceOptions
 */
export declare const ServiceOptions: {
    typeUrl: string;
    encode(message: ServiceOptions, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): ServiceOptions;
    fromPartial(object: DeepPartial<ServiceOptions>): ServiceOptions;
};
/**
 * @name MethodOptions
 * @package google.protobuf
 * @see proto type: google.protobuf.MethodOptions
 */
export declare const MethodOptions: {
    typeUrl: string;
    encode(message: MethodOptions, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): MethodOptions;
    fromPartial(object: DeepPartial<MethodOptions>): MethodOptions;
};
/**
 * @name UninterpretedOption
 * @package google.protobuf
 * @see proto type: google.protobuf.UninterpretedOption
 */
export declare const UninterpretedOption: {
    typeUrl: string;
    encode(message: UninterpretedOption, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): UninterpretedOption;
    fromPartial(object: DeepPartial<UninterpretedOption>): UninterpretedOption;
};
/**
 * @name UninterpretedOption_NamePart
 * @package google.protobuf
 * @see proto type: google.protobuf.NamePart
 */
export declare const UninterpretedOption_NamePart: {
    typeUrl: string;
    encode(message: UninterpretedOption_NamePart, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): UninterpretedOption_NamePart;
    fromPartial(object: DeepPartial<UninterpretedOption_NamePart>): UninterpretedOption_NamePart;
};
/**
 * @name SourceCodeInfo
 * @package google.protobuf
 * @see proto type: google.protobuf.SourceCodeInfo
 */
export declare const SourceCodeInfo: {
    typeUrl: string;
    encode(message: SourceCodeInfo, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): SourceCodeInfo;
    fromPartial(object: DeepPartial<SourceCodeInfo>): SourceCodeInfo;
};
/**
 * @name SourceCodeInfo_Location
 * @package google.protobuf
 * @see proto type: google.protobuf.Location
 */
export declare const SourceCodeInfo_Location: {
    typeUrl: string;
    encode(message: SourceCodeInfo_Location, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): SourceCodeInfo_Location;
    fromPartial(object: DeepPartial<SourceCodeInfo_Location>): SourceCodeInfo_Location;
};
/**
 * @name GeneratedCodeInfo
 * @package google.protobuf
 * @see proto type: google.protobuf.GeneratedCodeInfo
 */
export declare const GeneratedCodeInfo: {
    typeUrl: string;
    encode(message: GeneratedCodeInfo, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): GeneratedCodeInfo;
    fromPartial(object: DeepPartial<GeneratedCodeInfo>): GeneratedCodeInfo;
};
/**
 * @name GeneratedCodeInfo_Annotation
 * @package google.protobuf
 * @see proto type: google.protobuf.Annotation
 */
export declare const GeneratedCodeInfo_Annotation: {
    typeUrl: string;
    encode(message: GeneratedCodeInfo_Annotation, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): GeneratedCodeInfo_Annotation;
    fromPartial(object: DeepPartial<GeneratedCodeInfo_Annotation>): GeneratedCodeInfo_Annotation;
};
