using IntrusionDetectionSystem.Controllers;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class LogParserServiceCollectionExtensions
    {
        public static IServiceCollection AddLogParsers(this IServiceCollection services)
        {
            services.AddSingleton<ILogParser, NoticeLogParser>();

            services.AddSingleton<ILogParser, CipLogParser>();
            services.AddSingleton<ILogParser, ConnLogParser>();
            services.AddSingleton<ILogParser, ProfinetRpcLogParser>();
            services.AddSingleton<ILogParser, DceRpcLogParser>();
            services.AddSingleton<ILogParser, DhcpLogParser>();
            services.AddSingleton<ILogParser, DnsLogParser>();
            services.AddSingleton<ILogParser, DpdLogParser>();
            services.AddSingleton<ILogParser, EnipListIdentityLogParser>();
            services.AddSingleton<ILogParser, EnipLogParser>();
            services.AddSingleton<ILogParser, SmbFilesLogParser>();
            services.AddSingleton<ILogParser, FilesLogParser>();
            services.AddSingleton<ILogParser, FtpLogParser>();
            services.AddSingleton<ILogParser, HttpLogParser>();
            services.AddSingleton<ILogParser, IsoCotpLogParser>();
            services.AddSingleton<ILogParser, KerberosLogParser>();
            services.AddSingleton<ILogParser, ModbusLogParser>();
            services.AddSingleton<ILogParser, NtlmLogParser>();
            services.AddSingleton<ILogParser, NtpLogParser>();
            services.AddSingleton<ILogParser, PELogParser>();
            services.AddSingleton<ILogParser, ProfinetLogParser>();
            services.AddSingleton<ILogParser, RdpLogParser>();
            services.AddSingleton<ILogParser, RfbLogParser>();
            services.AddSingleton<ILogParser, S7CommLogParser>();
            services.AddSingleton<ILogParser, SmbMappingLogParser>();
            services.AddSingleton<ILogParser, SmtpLogParser>();
            services.AddSingleton<ILogParser, SnmpLogParser>();
            services.AddSingleton<ILogParser, SshLogParser>();
            services.AddSingleton<ILogParser, SslLogParser>();
            services.AddSingleton<ILogParser, SysLogParser>();
            services.AddSingleton<ILogParser, WeirdLogParser>();
            services.AddSingleton<ILogParser, X509LogParser>();

            services.AddSingleton<NoticeParser>();

            return services;
        }
    }
}
