use std::fmt::Display;

use bias_core::efi::smi::{SmiHandlerAnalyser, EFI_SMI_HANDLER_ANALYSIS};
use bias_core::ir::Address;
use bias_core::kb::function::Function;
use bias_core::kb::id::Identifiable;
use bias_core::project::ProjectContext;
use bias_core::Project;

use crate::bmatch::BMatcher;
use crate::group::Groups;
use crate::matcher::MatchContext;
use crate::schema::*;
use crate::MatchesRule;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
pub enum CodeLocation {
    #[serde(rename = "smi_handlers")]
    SmiHandlers,
    #[serde(rename = "child_sw_smi_handlers")]
    ChildSwSmiHandlers,
    #[serde(rename = "pch_smi_handlers")]
    PchSmiHandlers,
    #[serde(rename = "pch_apu_ras_smi_handlers")]
    PchApuRasSmiHandlers,
    #[serde(rename = "pch_acpi_smi_handlers")]
    PchAcpiSmiHandlers,
    #[serde(rename = "gpi_smi_handlers")]
    GpiSmiHandlers,
    #[serde(rename = "pch_gpi_smi_handlers")]
    PchGpiSmiHandlers,
    #[serde(rename = "gpio_unlock_smi_handlers")]
    GpioUnlockSmiHandlers,
    #[serde(rename = "pch_gpio_unlock_smi_handlers")]
    PchGpioUnlockSmiHandlers,
    #[serde(rename = "ichn_smi_handlers")]
    IchnSmiHandlers,
    #[serde(rename = "pch_ichn_smi_handlers")]
    PchIchnSmiHandlers,
    #[serde(rename = "io_trap_smi_handlers")]
    IoTrapSmiHandlers,
    #[serde(rename = "pch_io_trap_smi_handlers")]
    PchIoTrapSmiHandlers,
    #[serde(rename = "periodic_timer_smi_handlers")]
    PeriodicTimerSmiHandlers,
    #[serde(rename = "pch_periodic_timer_smi_handlers")]
    PchPeriodicTimerSmiHandlers,
    #[serde(rename = "pch_pcie_smi_handlers")]
    PchPcieSmiHandlers,
    #[serde(rename = "pch_misc_smi_handlers")]
    PchMiscSmiHandlers,
    #[serde(rename = "power_button_smi_handlers")]
    PowerButtonSmiHandlers,
    #[serde(rename = "pch_power_button_smi_handlers")]
    PchPowerButtonSmiHandlers,
    #[serde(rename = "pch_espi_smi_handlers")]
    PchEspiSmiHandlers,
    #[serde(rename = "standby_button_smi_handlers")]
    StandbyButtonSmiHandlers,
    #[serde(rename = "pch_standby_button_smi_handlers")]
    PchStandbyButtonSmiHandlers,
    #[serde(rename = "sw_smi_handlers")]
    SwSmiHandlers,
    #[serde(rename = "pch_sw_smi_handlers")]
    PchSwSmiHandlers,
    #[serde(rename = "sx_smi_handlers")]
    SxSmiHandlers,
    #[serde(rename = "pch_sx_smi_handlers")]
    PchSxSmiHandlers,
    #[serde(rename = "tco_smi_handlers")]
    TcoSmiHandlers,
    #[serde(rename = "pch_tco_smi_handlers")]
    PchTcoSmiHandlers,
    #[serde(rename = "usb_smi_handlers")]
    UsbSmiHandlers,
    #[serde(rename = "pch_usb_smi_handlers")]
    PchUsbSmiHandlers,
}

impl Display for CodeLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CodeLocation::SmiHandlers => "smi-handlers",
            CodeLocation::ChildSwSmiHandlers => "child-sw-smi-handlers",
            CodeLocation::PchSmiHandlers => "pch-smi-handlers",
            CodeLocation::PchApuRasSmiHandlers => "pch-apu-ras-smi-handlers",
            CodeLocation::PchAcpiSmiHandlers => "pch-acpi-smi-handlers",
            CodeLocation::GpiSmiHandlers => "gpi-smi-handlers",
            CodeLocation::PchGpiSmiHandlers => "pch-gpi-smi-handlers",
            CodeLocation::GpioUnlockSmiHandlers => "gpio-unlock-smi-handlers",
            CodeLocation::PchGpioUnlockSmiHandlers => "pch-gpio-unlock-smi-handlers",
            CodeLocation::IchnSmiHandlers => "ichn-smi-handlers",
            CodeLocation::PchIchnSmiHandlers => "pch-ichn-smi-handlers",
            CodeLocation::IoTrapSmiHandlers => "io-trap-smi-handlers",
            CodeLocation::PchIoTrapSmiHandlers => "pch-io-trap-smi-handlers",
            CodeLocation::PeriodicTimerSmiHandlers => "periodic-timer-smi-handlers",
            CodeLocation::PchPeriodicTimerSmiHandlers => "pch-periodic-timer-smi-handlers",
            CodeLocation::PchPcieSmiHandlers => "pch-pcie-smi-handlers",
            CodeLocation::PchMiscSmiHandlers => "pch-misc-smi-handlers",
            CodeLocation::PowerButtonSmiHandlers => "power-button-smi-handlers",
            CodeLocation::PchPowerButtonSmiHandlers => "pch-power-button-smi-handlers",
            CodeLocation::PchEspiSmiHandlers => "pch-espi-smi-handlers",
            CodeLocation::StandbyButtonSmiHandlers => "standby-button-smi-handlers",
            CodeLocation::PchStandbyButtonSmiHandlers => "pch-standby-button-smi-handlers",
            CodeLocation::SwSmiHandlers => "sw-smi-handlers",
            CodeLocation::PchSwSmiHandlers => "pch-sw-smi-handlers",
            CodeLocation::SxSmiHandlers => "sx-smi-handlers",
            CodeLocation::PchSxSmiHandlers => "pch-sx-smi-handlers",
            CodeLocation::TcoSmiHandlers => "tco-smi-handlers",
            CodeLocation::PchTcoSmiHandlers => "pch-tco-smi-handlers",
            CodeLocation::UsbSmiHandlers => "usb-smi-handlers",
            CodeLocation::PchUsbSmiHandlers => "pch-usb-smi-handlers",
        })
    }
}

impl CodeLocation {
    pub fn schema(&self, location: Address) -> FwHuntCheckLocation {
        match self {
            CodeLocation::SmiHandlers => FwHuntCheckLocation::SmiHandler {
                value: location.offset(),
            },
            CodeLocation::ChildSwSmiHandlers => FwHuntCheckLocation::ChildSwSmiHandler {
                value: location.offset(),
            },
            CodeLocation::PchSmiHandlers => FwHuntCheckLocation::PchSmiHandler {
                value: location.offset(),
            },
            CodeLocation::PchApuRasSmiHandlers => FwHuntCheckLocation::PchApuRasSmiHandler {
                value: location.offset(),
            },
            CodeLocation::PchAcpiSmiHandlers => FwHuntCheckLocation::PchAcpiSmiHandler {
                value: location.offset(),
            },
            CodeLocation::GpiSmiHandlers => FwHuntCheckLocation::GpiSmiHandler {
                value: location.offset(),
            },
            CodeLocation::PchGpiSmiHandlers => FwHuntCheckLocation::PchGpiSmiHandler {
                value: location.offset(),
            },
            CodeLocation::GpioUnlockSmiHandlers => FwHuntCheckLocation::GpioUnlockSmiHandler {
                value: location.offset(),
            },
            CodeLocation::PchGpioUnlockSmiHandlers => {
                FwHuntCheckLocation::PchGpioUnlockSmiHandler {
                    value: location.offset(),
                }
            }
            CodeLocation::IchnSmiHandlers => FwHuntCheckLocation::IchnSmiHandler {
                value: location.offset(),
            },
            CodeLocation::PchIchnSmiHandlers => FwHuntCheckLocation::PchIchnSmiHandler {
                value: location.offset(),
            },
            CodeLocation::IoTrapSmiHandlers => FwHuntCheckLocation::IoTrapSmiHandler {
                value: location.offset(),
            },
            CodeLocation::PchIoTrapSmiHandlers => FwHuntCheckLocation::PchIoTrapSmiHandler {
                value: location.offset(),
            },
            CodeLocation::PeriodicTimerSmiHandlers => {
                FwHuntCheckLocation::PeriodicTimerSmiHandler {
                    value: location.offset(),
                }
            }
            CodeLocation::PchPeriodicTimerSmiHandlers => {
                FwHuntCheckLocation::PchPeriodicTimerSmiHandler {
                    value: location.offset(),
                }
            }
            CodeLocation::PchPcieSmiHandlers => FwHuntCheckLocation::PchPcieSmiHandler {
                value: location.offset(),
            },
            CodeLocation::PchMiscSmiHandlers => FwHuntCheckLocation::PchMiscSmiHandler {
                value: location.offset(),
            },
            CodeLocation::PowerButtonSmiHandlers => FwHuntCheckLocation::PowerButtonSmiHandler {
                value: location.offset(),
            },
            CodeLocation::PchPowerButtonSmiHandlers => {
                FwHuntCheckLocation::PchPowerButtonSmiHandler {
                    value: location.offset(),
                }
            }
            CodeLocation::PchEspiSmiHandlers => FwHuntCheckLocation::PchEspiSmiHandler {
                value: location.offset(),
            },
            CodeLocation::StandbyButtonSmiHandlers => {
                FwHuntCheckLocation::StandbyButtonSmiHandler {
                    value: location.offset(),
                }
            }
            CodeLocation::PchStandbyButtonSmiHandlers => {
                FwHuntCheckLocation::PchStandbyButtonSmiHandler {
                    value: location.offset(),
                }
            }
            CodeLocation::SwSmiHandlers => FwHuntCheckLocation::SwSmiHandler {
                value: location.offset(),
            },
            CodeLocation::PchSwSmiHandlers => FwHuntCheckLocation::PchSwSmiHandler {
                value: location.offset(),
            },
            CodeLocation::SxSmiHandlers => FwHuntCheckLocation::SxSmiHandler {
                value: location.offset(),
            },
            CodeLocation::PchSxSmiHandlers => FwHuntCheckLocation::PchSxSmiHandler {
                value: location.offset(),
            },
            CodeLocation::TcoSmiHandlers => FwHuntCheckLocation::TcoSmiHandler {
                value: location.offset(),
            },
            CodeLocation::PchTcoSmiHandlers => FwHuntCheckLocation::PchTcoSmiHandler {
                value: location.offset(),
            },
            CodeLocation::UsbSmiHandlers => FwHuntCheckLocation::UsbSmiHandler {
                value: location.offset(),
            },
            CodeLocation::PchUsbSmiHandlers => FwHuntCheckLocation::PchUsbSmiHandler {
                value: location.offset(),
            },
        }
    }

    pub fn from_kind(kind: impl AsRef<str>) -> Option<CodeLocation> {
        match kind.as_ref() {
            "PCH_SMI_DISPATCH_PROTOCOL" => Some(CodeLocation::PchSmiHandlers),
            "PCH_ACPI_DISPATCH_PROTOCOL" => Some(CodeLocation::PchAcpiSmiHandlers),
            "FCH_SMM_APU_RAS_DISPATCH_PROTOCOL" => Some(CodeLocation::PchApuRasSmiHandlers),
            "FCH_SMM_GPI_DISPATCH2_PROTOCOL" => Some(CodeLocation::PchGpiSmiHandlers),
            "EFI_SMM_GPI_DISPATCH_PROTOCOL" | "EFI_SMM_GPI_DISPATCH2_PROTOCOL" => {
                Some(CodeLocation::GpiSmiHandlers)
            }
            "PCH_GPIO_UNLOCK_SMI_DISPATCH_PROTOCOL" => Some(CodeLocation::PchGpioUnlockSmiHandlers),
            "EFI_SMM_ICHN_DISPATCH_PROTOCOL"
            | "EFI_SMM_ICHN_DISPATCH2_PROTOCOL"
            | "EFI_SMM_ICHN_DISPATCH_EX_PROTOCOL"
            | "EFI_SMM_ICHN_DISPATCH2_EX_PROTOCOL" => Some(CodeLocation::IchnSmiHandlers),
            "FCH_SMM_IO_TRAP_DISPATCH2_PROTOCOL" => Some(CodeLocation::PchIoTrapSmiHandlers),
            "EFI_SMM_IO_TRAP_DISPATCH_PROTOCOL" | "EFI_SMM_IO_TRAP_DISPATCH2_PROTOCOL" => {
                Some(CodeLocation::IoTrapSmiHandlers)
            }
            "FCH_SMM_MISC_DISPATCH_PROTOCOL" => Some(CodeLocation::PchMiscSmiHandlers),
            "PCH_PCIE_SMI_DISPATCH_PROTOCOL" => Some(CodeLocation::PchPcieSmiHandlers),
            "FCH_SMM_PERIODICAL_DISPATCH2_PROTOCOL" => {
                Some(CodeLocation::PchPeriodicTimerSmiHandlers)
            }
            "EFI_SMM_PERIODIC_TIMER_DISPATCH_PROTOCOL"
            | "EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL" => {
                Some(CodeLocation::PeriodicTimerSmiHandlers)
            }
            "FCH_SMM_PWR_BTN_DISPATCH2_PROTOCOL" => Some(CodeLocation::PchPowerButtonSmiHandlers),
            "EFI_SMM_POWER_BUTTON_DISPATCH_PROTOCOL"
            | "EFI_SMM_POWER_BUTTON_DISPATCH2_PROTOCOL" => {
                Some(CodeLocation::PowerButtonSmiHandlers)
            }
            "PCH_ESPI_SMI_DISPATCH_PROTOCOL" => Some(CodeLocation::PchEspiSmiHandlers),
            "EFI_SMM_STANDBY_BUTTON_DISPATCH_PROTOCOL"
            | "EFI_SMM_STANDBY_BUTTON_DISPATCH2_PROTOCOL" => {
                Some(CodeLocation::StandbyButtonSmiHandlers)
            }
            "FCH_SMM_SW_DISPATCH2_PROTOCOL" => Some(CodeLocation::PchSwSmiHandlers),
            "EFI_SMM_SW_DISPATCH_PROTOCOL" | "EFI_SMM_SW_DISPATCH2_PROTOCOL" => {
                Some(CodeLocation::SwSmiHandlers)
            }
            "FCH_SMM_SX_DISPATCH2_PROTOCOL" => Some(CodeLocation::PchSxSmiHandlers),
            "EFI_SMM_SX_DISPATCH_PROTOCOL" | "EFI_SMM_SX_DISPATCH2_PROTOCOL" => {
                Some(CodeLocation::SxSmiHandlers)
            }
            "PCH_TCO_SMI_DISPATCH_PROTOCOL" => Some(CodeLocation::PchTcoSmiHandlers),
            "EFI_SMM_TCO_DISPATCH_PROTOCOL" => Some(CodeLocation::TcoSmiHandlers),
            "FCH_SMM_USB_DISPATCH_PROTOCOL" | "FCH_SMM_USB_DISPATCH2_PROTOCOL" => {
                Some(CodeLocation::PchUsbSmiHandlers)
            }
            "EFI_SMM_USB_DISPATCH_PROTOCOL" | "EFI_SMM_USB_DISPATCH2_PROTOCOL" => {
                Some(CodeLocation::UsbSmiHandlers)
            }
            _ => None,
        }
    }

    pub fn filter(&self, kind: impl AsRef<str>) -> bool {
        let kind = kind.as_ref();
        match self {
            CodeLocation::SmiHandlers => true,

            CodeLocation::PchSmiHandlers => ["PCH_SMI_DISPATCH_PROTOCOL"].contains(&kind),

            CodeLocation::PchAcpiSmiHandlers => ["PCH_ACPI_DISPATCH_PROTOCOL"].contains(&kind),
            CodeLocation::PchApuRasSmiHandlers => {
                ["FCH_SMM_APU_RAS_DISPATCH_PROTOCOL"].contains(&kind)
            }
            CodeLocation::PchGpiSmiHandlers => ["FCH_SMM_GPI_DISPATCH2_PROTOCOL"].contains(&kind),
            CodeLocation::GpiSmiHandlers => [
                "EFI_SMM_GPI_DISPATCH_PROTOCOL",
                "EFI_SMM_GPI_DISPATCH2_PROTOCOL",
            ]
            .contains(&kind),
            CodeLocation::PchGpioUnlockSmiHandlers => {
                ["PCH_GPIO_UNLOCK_SMI_DISPATCH_PROTOCOL"].contains(&kind)
            }
            CodeLocation::IchnSmiHandlers => [
                "EFI_SMM_ICHN_DISPATCH_PROTOCOL",
                "EFI_SMM_ICHN_DISPATCH2_PROTOCOL",
                "EFI_SMM_ICHN_DISPATCH_EX_PROTOCOL",
                "EFI_SMM_ICHN_DISPATCH2_EX_PROTOCOL",
            ]
            .contains(&kind),
            CodeLocation::PchIoTrapSmiHandlers => {
                ["FCH_SMM_IO_TRAP_DISPATCH2_PROTOCOL"].contains(&kind)
            }
            CodeLocation::IoTrapSmiHandlers => [
                "EFI_SMM_IO_TRAP_DISPATCH_PROTOCOL",
                "EFI_SMM_IO_TRAP_DISPATCH2_PROTOCOL",
            ]
            .contains(&kind),
            CodeLocation::PchMiscSmiHandlers => ["FCH_SMM_MISC_DISPATCH_PROTOCOL"].contains(&kind),
            CodeLocation::PchPcieSmiHandlers => ["PCH_PCIE_SMI_DISPATCH_PROTOCOL"].contains(&kind),
            CodeLocation::PchPeriodicTimerSmiHandlers => {
                ["FCH_SMM_PERIODICAL_DISPATCH2_PROTOCOL"].contains(&kind)
            }
            CodeLocation::PeriodicTimerSmiHandlers => [
                "EFI_SMM_PERIODIC_TIMER_DISPATCH_PROTOCOL",
                "EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL",
            ]
            .contains(&kind),
            CodeLocation::PchPowerButtonSmiHandlers => {
                ["FCH_SMM_PWR_BTN_DISPATCH2_PROTOCOL"].contains(&kind)
            }
            CodeLocation::PowerButtonSmiHandlers => [
                "EFI_SMM_POWER_BUTTON_DISPATCH_PROTOCOL",
                "EFI_SMM_POWER_BUTTON_DISPATCH2_PROTOCOL",
            ]
            .contains(&kind),
            CodeLocation::PchEspiSmiHandlers => ["PCH_ESPI_SMI_DISPATCH_PROTOCOL"].contains(&kind),
            CodeLocation::StandbyButtonSmiHandlers => [
                "EFI_SMM_STANDBY_BUTTON_DISPATCH_PROTOCOL",
                "EFI_SMM_STANDBY_BUTTON_DISPATCH2_PROTOCOL",
            ]
            .contains(&kind),
            CodeLocation::PchSwSmiHandlers => ["FCH_SMM_SW_DISPATCH2_PROTOCOL"].contains(&kind),
            CodeLocation::SwSmiHandlers => [
                "EFI_SMM_SW_DISPATCH_PROTOCOL",
                "EFI_SMM_SW_DISPATCH2_PROTOCOL",
            ]
            .contains(&kind),
            CodeLocation::PchSxSmiHandlers => ["FCH_SMM_SX_DISPATCH2_PROTOCOL"].contains(&kind),
            CodeLocation::SxSmiHandlers => [
                "EFI_SMM_SX_DISPATCH_PROTOCOL",
                "EFI_SMM_SX_DISPATCH2_PROTOCOL",
            ]
            .contains(&kind),
            CodeLocation::PchTcoSmiHandlers => ["PCH_TCO_SMI_DISPATCH_PROTOCOL"].contains(&kind),
            CodeLocation::TcoSmiHandlers => ["EFI_SMM_TCO_DISPATCH_PROTOCOL"].contains(&kind),
            CodeLocation::PchUsbSmiHandlers => [
                "FCH_SMM_USB_DISPATCH_PROTOCOL",
                "FCH_SMM_USB_DISPATCH2_PROTOCOL",
            ]
            .contains(&kind),
            CodeLocation::UsbSmiHandlers => [
                "EFI_SMM_USB_DISPATCH_PROTOCOL",
                "EFI_SMM_USB_DISPATCH2_PROTOCOL",
            ]
            .contains(&kind),

            _ => false,
        }
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    getset::Getters,
    getset::MutGetters,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct Code {
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(serialize_with = "crate::bmatch::BMatcher::ser_to_str")]
    #[serde(deserialize_with = "crate::bmatch::BMatcher::de_from_str")]
    pattern: BMatcher,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(default, rename = "place", skip_serializing_if = "Option::is_none")]
    place: Option<CodeLocation>,
}

impl Code {
    pub fn group() -> Groups<Code> {
        Groups::default()
    }

    pub fn from_pattern(value: impl AsRef<str>) -> Result<Self, crate::bmatch::Error> {
        Self::from_pattern_with(value, None)
    }

    pub fn from_pattern_with(
        value: impl AsRef<str>,
        place: impl Into<Option<CodeLocation>>,
    ) -> Result<Self, crate::bmatch::Error> {
        Ok(Self {
            pattern: value.as_ref().parse()?,
            place: place.into(),
        })
    }

    pub fn from_pattern_parts(
        pattern: impl AsRef<[u8]>,
        mask: impl AsRef<[u8]>,
    ) -> Result<Self, crate::bmatch::Error> {
        Self::from_pattern_parts_with(pattern, mask, None)
    }

    pub fn from_pattern_parts_with(
        pattern: impl AsRef<[u8]>,
        mask: impl AsRef<[u8]>,
        place: impl Into<Option<CodeLocation>>,
    ) -> Result<Self, crate::bmatch::Error> {
        Ok(Self {
            pattern: BMatcher::from_parts(pattern.as_ref(), mask.as_ref())?,
            place: place.into(),
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::from_bytes_with(bytes, None)
    }

    pub fn from_bytes_with(bytes: &[u8], place: impl Into<Option<CodeLocation>>) -> Self {
        Self {
            pattern: BMatcher::from_bytes(bytes),
            place: place.into(),
        }
    }

    fn function_bytes<'a, C>(project: C, function: &Function) -> impl Iterator<Item = &'a [u8]>
    where
        C: Into<ProjectContext<'a>>,
    {
        let project = project.into();

        function
            .chunks(project.cbtable)
            .into_iter()
            .filter_map(|iv| {
                let start = iv.start;
                let last = iv.end;
                let count = usize::from(last - start);

                let region = project.memory.find_region(start)?;
                region.view_bytes(start, count).ok()
            })
    }

    fn match_recursive<'a, C>(
        &self,
        context: &mut MatchContext,
        project: C,
        handler: &Address,
    ) -> bool
    where
        C: Into<ProjectContext<'a>>,
    {
        let project = project.into();
        if let Some(f) = project.ftable.get_point(handler) {
            tracing::trace!(
                "scanning for {} in function at {}",
                self.pattern,
                f.address()
            );

            if let Some(offset) =
                Self::function_bytes(project, f).find_map(|b| self.pattern.position(b))
            {
                let location = f.address() + offset;
                tracing::trace!("found {} at {}", self.pattern, location);
                if let Some(place) = self.place().as_ref() {
                    context.describe(FwHuntCheckMatch::Code {
                        value: self.pattern.to_string(),
                        length: self.pattern.len(),
                        location: place.schema(location),
                    });
                } else {
                    context.describe(FwHuntCheckMatch::Code {
                        value: self.pattern.to_string(),
                        length: self.pattern.len(),
                        location: FwHuntCheckLocation::Address {
                            value: location.offset(),
                        },
                    });
                }
                context.push_provenance(location);
                return true;
            }

            let mut callees = Vec::new();

            // FIXME: ideally it would be nice to have an early exit from this function to avoid
            // allocating a vec to check...
            project
                .icfg
                .for_each_called_by(f.id(), project, |ff, _| callees.push(ff.id()));

            callees.into_iter().any(|f| {
                let f = &project.ftable[f];
                tracing::trace!(
                    "scanning for {} in function at {}",
                    self.pattern,
                    f.address()
                );
                if let Some(offset) =
                    Self::function_bytes(project, f).find_map(|b| self.pattern.position(b))
                {
                    let location = f.address() + offset;
                    tracing::trace!("found {} at {}", self.pattern, location);
                    if let Some(place) = self.place().as_ref() {
                        context.describe(FwHuntCheckMatch::Code {
                            value: self.pattern.to_string(),
                            length: self.pattern.len(),
                            location: FwHuntCheckLocation::FunctionCalledVia {
                                value: Box::new(FwHuntCalledViaLocations {
                                    function: FwHuntCheckLocation::Address {
                                        value: location.offset(),
                                    },
                                    handler: place.schema(*handler),
                                }),
                            },
                        });
                    } else {
                        context.describe(FwHuntCheckMatch::Code {
                            value: self.pattern.to_string(),
                            length: self.pattern.len(),
                            location: FwHuntCheckLocation::FunctionCalledVia {
                                value: Box::new(FwHuntCalledViaLocations {
                                    function: FwHuntCheckLocation::Address {
                                        value: location.offset(),
                                    },
                                    handler: FwHuntCheckLocation::FunctionAddress {
                                        value: handler.offset(),
                                    },
                                }),
                            },
                        });
                    }
                    context.push_provenance(location);
                    true
                } else {
                    false
                }
            })
        } else {
            false
        }
    }
}

impl Display for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(place) = self.place() {
            write!(f, "{} in {}", self.pattern, place,)
        } else {
            self.pattern.fmt(f)
        }
    }
}

impl MatchesRule for Code {
    fn matches_rule(&self, context: &mut MatchContext, project: &Project) -> bool {
        tracing::trace!("scanning for code pattern {self}");
        if let Some(ref place) = self.place {
            let handlers = project
                .analyses()
                .get::<SmiHandlerAnalyser>(EFI_SMI_HANDLER_ANALYSIS)
                .unwrap();
            match place {
                CodeLocation::SmiHandlers => {
                    handlers.smi_handlers().values().flatten().any(|handler| {
                        tracing::trace!("processing SMI handler {handler}");
                        self.match_recursive(context, project, handler)
                    })
                }
                CodeLocation::ChildSwSmiHandlers => {
                    handlers.child_sw_smi_handlers().iter().any(|handler| {
                        tracing::trace!("processing child SMI handler {handler}");
                        self.match_recursive(context, project, handler)
                    })
                }
                _ => handlers
                    .smi_handlers()
                    .iter()
                    .filter_map(|(k, v)| if place.filter(k) { Some(v) } else { None })
                    .flatten()
                    .any(|handler| {
                        tracing::trace!("processing SMI handler {handler}");
                        self.match_recursive(context, project, handler)
                    }),
            }
        } else {
            if self.pattern.matches_rule(context, project) {
                let prov = context.pending_provenance().unwrap();
                context.describe(FwHuntCheckMatch::Code {
                    value: self.pattern.to_string(),
                    length: self.pattern.len(),
                    location: FwHuntCheckLocation::Address {
                        value: prov.offset(),
                    },
                });
                true
            } else {
                false
            }
        }
    }
}
