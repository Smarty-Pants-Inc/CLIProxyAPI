package config

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// sdkConfigDecode is deliberately distinct from SDKConfig. SDKConfig has a
// standalone YAML validation hook, while the full Config decoder must inline
// all SDK and server fields without invoking that hook for the whole document.
type sdkConfigDecode SDKConfig

// yaml.v3 also omits inline structs with UnmarshalYAML hooks when encoding.
// Derive a method-free wire type from Config instead of duplicating its schema.
var configYAMLType = func() reflect.Type {
	typ := reflect.TypeOf(Config{})
	fields := make([]reflect.StructField, 0, typ.NumField())
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		if field.PkgPath != "" {
			continue
		}
		if field.Type == reflect.TypeOf(SDKConfig{}) {
			field.Type = reflect.TypeOf(sdkConfigDecode{})
		}
		field.Anonymous = false
		fields = append(fields, field)
	}
	return reflect.StructOf(fields)
}()

func (cfg legacyConfig) MarshalYAML() (any, error) {
	source := reflect.ValueOf(cfg)
	value := reflect.New(configYAMLType).Elem()
	for index := 0; index < value.NumField(); index++ {
		field := value.Field(index)
		field.Set(source.FieldByName(configYAMLType.Field(index).Name).Convert(field.Type()))
	}
	return value.Interface(), nil
}

// decodeConfigNode starts with the existing snapshot, decodes the method-free
// SDK alias, then decodes each exported non-inline Config field by its YAML tag.
// Runtime-only and unexported fields therefore remain attached to the snapshot.
func decodeConfigNode(root *yaml.Node, initial Config) (Config, error) {
	decoded := initial.CloneForRuntime()
	if decoded == nil {
		decoded = &Config{}
	}

	sdk := sdkConfigDecode(decoded.SDKConfig)
	if err := root.Decode(&sdk); err != nil {
		return Config{}, err
	}
	decoded.SDKConfig = SDKConfig(sdk)

	value := reflect.ValueOf(decoded).Elem()
	typ := value.Type()
	for index := 0; index < typ.NumField(); index++ {
		fieldInfo := typ.Field(index)
		if fieldInfo.Anonymous || fieldInfo.PkgPath != "" {
			continue
		}
		fieldName := strings.Split(fieldInfo.Tag.Get("yaml"), ",")[0]
		if fieldName == "" || fieldName == "-" {
			continue
		}
		node := yamlPath(root, fieldName)
		if node == nil {
			continue
		}
		if err := node.Decode(value.Field(index).Addr().Interface()); err != nil {
			return Config{}, fmt.Errorf("decode %s: %w", fieldName, err)
		}
	}
	return *decoded, nil
}

// validateConfigNodeKnownFields preserves ValidateV8Config's strict decoder
// behavior without maintaining a second copy of Config's field schema.
func validateConfigNodeKnownFields(root *yaml.Node) error {
	fields := configYAMLFieldTypes()
	if root == nil || root.Kind != yaml.MappingNode {
		return fmt.Errorf("config must be a mapping")
	}
	for index := 0; index+1 < len(root.Content); index += 2 {
		name := root.Content[index].Value
		fieldType, ok := fields[name]
		if !ok {
			return fmt.Errorf("field %s not found in config", name)
		}
		if err := decodeKnownConfigValue(root.Content[index+1], fieldType); err != nil {
			return fmt.Errorf("decode %s: %w", name, err)
		}
	}
	return nil
}

func configYAMLFieldTypes() map[string]reflect.Type {
	fields := make(map[string]reflect.Type)
	addFields := func(typ reflect.Type) {
		for index := 0; index < typ.NumField(); index++ {
			field := typ.Field(index)
			if field.PkgPath != "" && !field.Anonymous {
				continue
			}
			name := strings.Split(field.Tag.Get("yaml"), ",")[0]
			if name == "" || name == "-" {
				continue
			}
			fields[name] = field.Type
		}
	}
	configType := reflect.TypeOf(Config{})
	for index := 0; index < configType.NumField(); index++ {
		field := configType.Field(index)
		if field.Anonymous {
			addFields(reflect.TypeOf(sdkConfigDecode{}))
			continue
		}
		if field.PkgPath != "" {
			continue
		}
		name := strings.Split(field.Tag.Get("yaml"), ",")[0]
		if name != "" && name != "-" {
			fields[name] = field.Type
		}
	}
	return fields
}

func decodeKnownConfigValue(node *yaml.Node, typ reflect.Type) error {
	data, err := yaml.Marshal(node)
	if err != nil {
		return err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	value := reflect.New(typ)
	return decoder.Decode(value.Interface())
}
