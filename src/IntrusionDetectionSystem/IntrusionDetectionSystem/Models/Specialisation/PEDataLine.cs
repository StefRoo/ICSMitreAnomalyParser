using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class PEDataLine : DataLine
    {
        [DataMember(Name = "id")]
        public string Id { get; internal set; }

        [DataMember(Name = "machine")]
        public string Machine { get; internal set; }

        [DataMember(Name = "compile_ts")]
        public string CompileTime { get; internal set; }

        [DataMember(Name = "os")]
        public string OperatingSystem { get; internal set; }

        [DataMember(Name = "subsystem")]
        public string Subsystem { get; internal set; }

        [DataMember(Name = "is_exe")]
        public string IsExe { get; internal set; }

        [DataMember(Name = "is_64bit")]
        public string Is64Bit { get; internal set; }

        [DataMember(Name = "uses_aslr")]
        public string UsesAslr { get; internal set; }

        [DataMember(Name = "uses_dep")]
        public string UsesDep { get; internal set; }

        [DataMember(Name = "uses_code_integrity")]
        public string UsesCodeIntegrity { get; internal set; }

        [DataMember(Name = "uses_seh")]
        public string UsesSeh { get; internal set; }

        [DataMember(Name = "has_import_table")]
        public string HasImportTable { get; internal set; }

        [DataMember(Name = "has_export_table")]
        public string HasExportTable { get; internal set; }

        [DataMember(Name = "has_cert_table")]
        public string HasCertTable { get; internal set; }

        [DataMember(Name = "has_debug_data")]
        public string HasDebugData { get; internal set; }

        [DataMember(Name = "section_names")]
        public string SectionNames { get; internal set; }
    }
}
