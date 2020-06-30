namespace IntrusionDetectionSystem.Models
{
    public enum IcsMitreTechnique
    {
        // Initial Access
        DataHistorianCompromise,
        DriveByCompromise,
        EngineeringWorkstationCompromise,
        ExploitPublicFacingApplication,
        InitialAccessExternalRemoteServices,
        InternetAccessibleDevice,
        ReplicationThroughRemovableMedia,
        SpearphishingAttachment,
        SupplyChainCompromise,
        WirelessCompromise,

        // Execution
        ExecutionChangeProgramState,
        CommandLineInterface,
        ExecutionThroughAPI,
        GraphicalUserInterface,
        ManInTheMiddle,
        ExecutionProgramOrganizationUnits,
        ExecutionProjectFileInfection,
        Scripting,
        UserExecution,

        // Persistence
        Hooking,
        PersistenceModuleFirmware,
        PersistenceProgramDownload,
        PersistenceProjectFileInfection,
        PersistenceSystemFirmware,
        PersistenceValidAccounts,

        // Evasion
        ExploitationForEvasion,
        IndicatorRemovalOnHost,
        EvasionMasquerading,
        EvasionRogueMasterDevice,
        EvasionRootkit,
        EvasionSpoofReportingMessage,
        EvasionUtilizeOrChangeOperatingMode,

        // Discovery
        ControlDeviceIdentification,
        IOModuleDiscovery,
        NetworkConnectionEnumeration,
        NetworkServiceScanning,
        NetworkSniffing,
        RemoteSystemDiscovery,
        SerialConnectionEnumeration,

        // Lateral Movement
        DefaultCredentials,
        ExploitationOfRemoteServices,
        LateralMovementExternalRemoteServices,
        LateralMovementProgramOrganizationUnits,
        RemoteFileCopy,
        LateralMovementValidAccounts,

        // Collection
        AutomatedCollection,
        DataFromInformationRepositories,
        DetectOperatingMode,
        DetectProgramState,
        IOImage,
        LocationIdentification,
        MonitorProcessState,
        PointAndTagIdentification,
        ProgramUpload,
        RoleIdentification,
        ScreenCapture,

        // Command and Control
        CommonlyUsedPort,
        ConnectionProxy,
        StandardApplicationLayerProtocol,

        // Inhibit Response Function
        ActivateFirmwareUpdateMode,
        AlarmSuppression,
        BlockCommandMessage,
        BlockReportingMessage,
        BlockSerialCOM,
        DataDestruction,
        DenialOfService,
        DeviceRestartOrShutdown,
        ManipulateIOImage,
        ModifyAlarmSettings,
        InhibitResponseFunctionModifyControlLogic,
        InhibitResponseFunctionProgramDownload,
        InhibitResponseFunctionRootkit,
        InhibitResponseFunctionSystemFirmware,
        InhibitResponseFunctionUtilizeOrChangeOperatingMode,

        // Impair Process Control
        BruteForceIO,
        ImpairProcessControlChangeProgramState,
        ImpairProcessControlMasquerading,
        ImpairProcessControlModifyControlLogic,
        ModifyParameter,
        ImpairProcessControlModuleFirmware,
        ImpairProcessControlProgramDownload,
        ImpairProcessControlRogueMasterDevice,
        ServiceStop,
        ImpairProcessControlSpoofReportingMessage,
        UnauthorizedCommandMessage
    }
}
