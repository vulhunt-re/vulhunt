use serde::{Deserialize, Serialize};

#[allow(unused)]
pub trait FwHuntMatchVisitor {
    fn visit_file_offset(&mut self, offset: &mut u64) {}

    fn visit_function_name(&mut self, name: &mut String) {}
    fn visit_function_address(&mut self, address: &mut u64) {}

    fn visit_function_caller(&mut self, location: &mut FwHuntCheckLocation) {
        self.visit_location(location)
    }

    fn visit_function_callee(&mut self, location: &mut FwHuntCheckLocation) {
        self.visit_location(location)
    }

    fn visit_function_called_via(&mut self, info: &mut FwHuntCalledViaLocations) {
        self.visit_function_caller(&mut info.handler);
        self.visit_function_callee(&mut info.function);
    }

    fn visit_function_call(&mut self, info: &mut FwHuntCallLocations) {
        self.visit_function_caller(&mut info.location);
        self.visit_function_callee(&mut info.target);
    }

    fn visit_location(&mut self, location: &mut FwHuntCheckLocation) {
        use FwHuntCheckLocation::*;
        match location {
            Address { value } => self.visit_function_address(value),
            Offset { value } => self.visit_file_offset(value),

            FunctionAddress { value } => self.visit_function_address(value),
            FunctionCall { value } => self.visit_function_call(value),
            FunctionCalledVia { value } => self.visit_function_called_via(value),
            FunctionName { value } => self.visit_function_name(value),

            SmiHandler { value } => self.visit_function_address(value),
            ChildSwSmiHandler { value } => self.visit_function_address(value),
            PchSmiHandler { value } => self.visit_function_address(value),
            PchApuRasSmiHandler { value } => self.visit_function_address(value),
            AcpiDisSmiHandler { value } => self.visit_function_address(value),
            AcpiEnSmiHandler { value } => self.visit_function_address(value),
            PchAcpiSmiHandler { value } => self.visit_function_address(value),
            GpiSmiHandler { value } => self.visit_function_address(value),
            PchGpiSmiHandler { value } => self.visit_function_address(value),
            GpioUnlockSmiHandler { value } => self.visit_function_address(value),
            PchGpioUnlockSmiHandler { value } => self.visit_function_address(value),
            IchnSmiHandler { value } => self.visit_function_address(value),
            PchIchnSmiHandler { value } => self.visit_function_address(value),
            IoTrapSmiHandler { value } => self.visit_function_address(value),
            PchIoTrapSmiHandler { value } => self.visit_function_address(value),
            PeriodicTimerSmiHandler { value } => self.visit_function_address(value),
            PchPeriodicTimerSmiHandler { value } => self.visit_function_address(value),
            PchPcieSmiHandler { value } => self.visit_function_address(value),
            PchMiscSmiHandler { value } => self.visit_function_address(value),
            PowerButtonSmiHandler { value } => self.visit_function_address(value),
            PchPowerButtonSmiHandler { value } => self.visit_function_address(value),
            PchEspiSmiHandler { value } => self.visit_function_address(value),
            StandbyButtonSmiHandler { value } => self.visit_function_address(value),
            PchStandbyButtonSmiHandler { value } => self.visit_function_address(value),
            SwSmiHandler { value } => self.visit_function_address(value),
            PchSwSmiHandler { value } => self.visit_function_address(value),
            SxSmiHandler { value } => self.visit_function_address(value),
            PchSxSmiHandler { value } => self.visit_function_address(value),
            TcoSmiHandler { value } => self.visit_function_address(value),
            PchTcoSmiHandler { value } => self.visit_function_address(value),
            UsbSmiHandler { value } => self.visit_function_address(value),
            PchUsbSmiHandler { value } => self.visit_function_address(value),
        }
    }

    fn visit_ascii_string(
        &mut self,
        value: &mut String,
        location: &mut FwHuntCheckLocation,
        length: &mut usize,
    ) {
        self.visit_location(location);
    }

    fn visit_wide_string(
        &mut self,
        value: &mut String,
        location: &mut FwHuntCheckLocation,
        length: &mut usize,
    ) {
        self.visit_location(location);
    }

    fn visit_hex_string(
        &mut self,
        value: &mut String,
        location: &mut FwHuntCheckLocation,
        length: &mut usize,
    ) {
        self.visit_location(location);
    }

    fn visit_byte_pattern(
        &mut self,
        value: &mut String,
        location: &mut FwHuntCheckLocation,
        length: &mut usize,
    ) {
        self.visit_location(location);
    }

    fn visit_code_pattern(
        &mut self,
        value: &mut String,
        location: &mut FwHuntCheckLocation,
        length: &mut usize,
    ) {
        self.visit_location(location);
    }

    fn visit_guid(&mut self, value: &mut String, locations: &mut Vec<FwHuntCheckLocation>) {
        for location in locations.iter_mut() {
            self.visit_location(location);
        }
    }

    fn visit_nvram_variable(
        &mut self,
        value: &mut String,
        location: &mut FwHuntCheckLocation,
    ) {
        self.visit_location(location);
    }

    fn visit_ppi(
        &mut self,
        value: &mut String,
        location: &mut FwHuntCheckLocation,
    ) {
        self.visit_location(location);
    }

    fn visit_protocol(
        &mut self,
        value: &mut String,
        location: &mut FwHuntCheckLocation,
    ) {
        self.visit_location(location);
    }

    fn visit_match(&mut self, check: &mut FwHuntCheckMatch) {
        use FwHuntCheckMatch::*;
        match check {
            AsciiString {
                value,
                length,
                location,
            } => self.visit_ascii_string(value, location, length),
            HexString {
                value,
                length,
                location,
            } => self.visit_hex_string(value, location, length),
            WideString {
                value,
                length,
                location,
            } => self.visit_wide_string(value, location, length),

            Code {
                value,
                length,
                location,
            } => self.visit_code_pattern(value, location, length),
            Pattern {
                value,
                length,
                location,
            } => self.visit_byte_pattern(value, location, length),

            Guid { value, locations } => self.visit_guid(value, locations),

            NvramVariable { value, location } => self.visit_nvram_variable(value, location),
            Ppi { value, location } => self.visit_ppi(value, location),
            Protocol { value, location } => self.visit_protocol(value, location),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct FwHuntCallLocations {
    pub location: FwHuntCheckLocation,
    pub target: FwHuntCheckLocation,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct FwHuntCalledViaLocations {
    pub function: FwHuntCheckLocation,
    pub handler: FwHuntCheckLocation,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum FwHuntCheckLocation {
    #[serde(rename = "address")]
    Address { value: u64 },
    #[serde(rename = "offset")]
    Offset { value: u64 },

    #[serde(rename = "function-address")]
    FunctionAddress { value: u64 },
    #[serde(rename = "function-call")]
    FunctionCall { value: Box<FwHuntCallLocations> },
    #[serde(rename = "function-called-via")]
    FunctionCalledVia {
        value: Box<FwHuntCalledViaLocations>,
    },
    #[serde(rename = "function-name")]
    FunctionName { value: String },

    #[serde(rename = "smi-handler")]
    SmiHandler { value: u64 },
    #[serde(rename = "child-sw-smi-handler")]
    ChildSwSmiHandler { value: u64 },
    #[serde(rename = "pch-smi-handler")]
    PchSmiHandler { value: u64 },
    #[serde(rename = "pch-apu-ras-smi-handler")]
    PchApuRasSmiHandler { value: u64 },
    #[serde(rename = "acpi-dis-smi-handler")]
    AcpiDisSmiHandler { value: u64 },
    #[serde(rename = "acpi-en-smi-handler")]
    AcpiEnSmiHandler { value: u64 },
    #[serde(rename = "pch-acpi-smi-handler")]
    PchAcpiSmiHandler { value: u64 },
    #[serde(rename = "gpi-smi-handler")]
    GpiSmiHandler { value: u64 },
    #[serde(rename = "pch-gpi-smi-handler")]
    PchGpiSmiHandler { value: u64 },
    #[serde(rename = "gpio-unlock-smi-handler")]
    GpioUnlockSmiHandler { value: u64 },
    #[serde(rename = "pch-gpio-unlock-smi-handler")]
    PchGpioUnlockSmiHandler { value: u64 },
    #[serde(rename = "ichn-smi-handler")]
    IchnSmiHandler { value: u64 },
    #[serde(rename = "pch-ichn-smi-handler")]
    PchIchnSmiHandler { value: u64 },
    #[serde(rename = "io-trap-smi-handler")]
    IoTrapSmiHandler { value: u64 },
    #[serde(rename = "pch-io-trap-smi-handler")]
    PchIoTrapSmiHandler { value: u64 },
    #[serde(rename = "periodic-timer-smi-handler")]
    PeriodicTimerSmiHandler { value: u64 },
    #[serde(rename = "pch-periodic-timer-smi-handler")]
    PchPeriodicTimerSmiHandler { value: u64 },
    #[serde(rename = "pch-pcie-smi-handler")]
    PchPcieSmiHandler { value: u64 },
    #[serde(rename = "pch-misc-smi-handler")]
    PchMiscSmiHandler { value: u64 },
    #[serde(rename = "power-button-smi-handler")]
    PowerButtonSmiHandler { value: u64 },
    #[serde(rename = "pch-power-button-smi-handler")]
    PchPowerButtonSmiHandler { value: u64 },
    #[serde(rename = "pch-espi-smi-handler")]
    PchEspiSmiHandler { value: u64 },
    #[serde(rename = "standby-button-smi-handler")]
    StandbyButtonSmiHandler { value: u64 },
    #[serde(rename = "pch-standby-button-smi-handler")]
    PchStandbyButtonSmiHandler { value: u64 },
    #[serde(rename = "sw-smi-handler")]
    SwSmiHandler { value: u64 },
    #[serde(rename = "pch-sw-smi-handler")]
    PchSwSmiHandler { value: u64 },
    #[serde(rename = "sx-smi-handler")]
    SxSmiHandler { value: u64 },
    #[serde(rename = "pch-sx-smi-handler")]
    PchSxSmiHandler { value: u64 },
    #[serde(rename = "tco-smi-handler")]
    TcoSmiHandler { value: u64 },
    #[serde(rename = "pch-tco-smi-handler")]
    PchTcoSmiHandler { value: u64 },
    #[serde(rename = "usb-smi-handler")]
    UsbSmiHandler { value: u64 },
    #[serde(rename = "pch-usb-smi-handler")]
    PchUsbSmiHandler { value: u64 },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum FwHuntCheckMatch {
    #[serde(rename = "ascii-string")]
    AsciiString {
        value: String,
        length: usize,
        location: FwHuntCheckLocation,
    },
    #[serde(rename = "hex-string")]
    HexString {
        value: String,
        length: usize,
        location: FwHuntCheckLocation,
    },
    #[serde(rename = "wide-string")]
    WideString {
        value: String,
        length: usize,
        location: FwHuntCheckLocation,
    },

    #[serde(rename = "code")]
    Code {
        value: String,
        length: usize,
        location: FwHuntCheckLocation,
    },
    #[serde(rename = "byte-string-pattern")]
    Pattern {
        value: String,
        length: usize,
        location: FwHuntCheckLocation,
    },

    #[serde(rename = "guid-xref")]
    Guid {
        value: String,
        locations: Vec<FwHuntCheckLocation>,
    },

    #[serde(rename = "nvram-variable-use")]
    NvramVariable {
        value: String,
        location: FwHuntCheckLocation,
    },
    #[serde(rename = "ppi-use")]
    Ppi {
        value: String,
        location: FwHuntCheckLocation,
    },
    Protocol {
        value: String,
        location: FwHuntCheckLocation,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FwHuntCheckDetails {
    pub namespace: String,
    pub variant: String,
    pub provenance: Vec<FwHuntCheckMatch>,
}
