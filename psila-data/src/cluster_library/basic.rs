//! # Basic Cluster

use crate::Error;
use core::convert::TryFrom;

/// Basic cluster
pub const CLUSTER: u16 = 0x0000;
/// Basic cluster attribute, library version
pub const ATTR_LIBRARY_VERSION: u16 = 0x0000;
/// Basic cluster attribute, application version
pub const ATTR_APPLICATION_VERSION: u16 = 0x0001;
/// Basic cluster attribute, stack version
pub const ATTR_STACK_VERSION: u16 = 0x0002;
/// Basic cluster attribute, hardware version
pub const ATTR_HARDWARE_VERSION: u16 = 0x0003;
/// Basic cluster attribute, manufacturer name
pub const ATTR_MANUFACTURER_NAME: u16 = 0x0004;
/// Basic cluster attribute, model identifier
pub const ATTR_MODEL_IDENTIFIER: u16 = 0x0005;
/// Basic cluster attribute, date code, YYYYMMDD
pub const ATTR_DATE_CODE: u16 = 0x0006;
/// Basic cluster attribute, power source
pub const ATTR_POWER_SOURCE: u16 = 0x0007;
/// Basic cluster attribute, location description
pub const ATTR_LOCATION_DESCRIPTION: u16 = 0x0010;
/// Basic cluster attribute, location description
pub const ATTR_PHYSICAL_ENVIRONMENT: u16 = 0x0011;
/// Basic cluster attribute, location description
pub const ATTR_DEVICE_ENABLED: u16 = 0x0012;
/// Basic cluster attribute, location description
pub const ATTR_ALARM_MASK: u16 = 0x0013;
/// Basic cluster attribute, location description
pub const ATTR_DISABLE_LOCAL_CONFIGURATION: u16 = 0x0014;
/// Basic cluster attribute, location description
pub const ATTR_SOFTWARE_BUILD_IDENTIFIER: u16 = 0x4000;

/// Basic cluster command, reset to factory defaults
pub const CMD_RESET: u8 = 0x00;

extended_enum!(
    /// Power source
    PowerSource, u8,
    /// Unknown
    Unknown => 0x00,
    /// Mains power, single phase
    Mains => 0x01,
    /// Mains power, three phase
    MainsThreePhase => 0x02,
    /// Battery
    Battery => 0x03,
    /// Direct current
    Dc => 0x04,
    /// Emergency mains constantly powered
    EmergencyConstant => 0x05,
    /// Emergency mains and transfer switch
    EmergencySwitched => 0x06,
);

extended_enum!(
    /// Physical environment in which the device will operate
    PhysicalEnvironment, u8,
    Unspecified => 0x00,
    Atrium => 0x01,
    Bar => 0x02,
    Courtyard => 0x03,
    Bathroom => 0x04,
    Bedroom => 0x05,
    BilliardRoom => 0x06,
    UtilityRoom => 0x07,
    Cellar => 0x08,
    StorageCloset => 0x09,
    Theater => 0x0a,
    Office => 0x0b,
    Deck => 0x0c,
    Den => 0x0d,
    DiningRoom => 0x0e,
    ElectricalRoom => 0x0f,
    Elevator => 0x10,
    Entry => 0x11,
    FamilyRoom => 0x12,
    MainFloor => 0x13,
    Upstairs => 0x14,
    Downstairs => 0x15,
    Basement => 0x16,
    Gallery => 0x17,
    GameRoom => 0x18,
    Garage => 0x19,
    Gym => 0x1a,
    Hallway => 0x1b,
    House => 0x1c,
    Kitchen => 0x1d,
    LaundryRoom => 0x1e,
    Library => 0x1f,
    MasterBedroom => 0x20,
    MudRoom => 0x21,
    Nursery => 0x22,
    Pantry => 0x23,
    OfficeOther => 0x24,
    Outside => 0x25,
    Pool => 0x26,
    Porch => 0x27,
    SewingRoom => 0x28,
    SittingRoom => 0x29,
    Stairway => 0x2a,
    Yard => 0x2b,
    Attic => 0x2c,
    HotTub => 0x2d,
    LivingRoom => 0x2e,
    Sauna => 0x2f,
    Workshop => 0x30,
    GuestBedroom => 0x31,
    GuestBath => 0x32,
    PowderRoom => 0x33,
    BackYard => 0x34,
    FrontYard => 0x35,
    Patio => 0x36,
    Driveway => 0x37,
    SunRoom => 0x38,
    LivingRoomOther => 0x39,
    Spa => 0x3a,
    Whirlpool => 0x3b,
    Shed => 0x3c,
    EquipmentStorage => 0x3d,
    HobbyRoom => 0x3e,
    Fountain => 0x3f,
    Pond => 0x40,
    ReceptionRoom => 0x41,
    BreakfastRoom => 0x42,
    Nook => 0x43,
    Garden => 0x44,
    Balcony => 0x45,
    PanicRoom => 0x46,
    Terrace => 0x47,
    Roof => 0x48,
    Toilet => 0x49,
    ToiletMain => 0x4a,
    OutsideToilet => 0x4b,
    ShowerRoom => 0x4c,
    Study => 0x4d,
    FrontGarden => 0x4e,
    BackGarden => 0x4f,
    Kettle => 0x50,
    Television => 0x51,
    Stove => 0x52,
    Microwave => 0x53,
    Toaster => 0x54,
    Vacuume => 0x55,
    Appliance => 0x56,
    FronDoor => 0x57,
    BackDoor => 0x58,
    FridgeDoor => 0x59,
    MedicalCabinetDoor => 0x60,
    WardrobeDoor => 0x61,
    FrontCupboardDoor => 0x62,
    OtherDoor => 0x63,
    WaitingRoom => 0x64,
    TriageRoom => 0x65,
    DoctorsOffice => 0x66,
    PatientsPrivateRoom => 0x67,
    ConsultationRoom => 0x68,
    NurseStation => 0x69,
    Ward => 0x6a,
    Corridor => 0x6b,
    OperatingTheater => 0x6c,
    DentalSurgeryRoom => 0x6d,
    MedicalImagingRoom => 0x6e,
    DecontaminationRoom => 0x6f,
    Unknown => 0xff,
);
