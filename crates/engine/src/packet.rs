//! A single concrete packet, for counterexamples.
//!
//! Everything else in this crate works in sets, because a set is the complete
//! answer and a witness is not. The one place a single packet is the right
//! output is a failed assertion: "this property does not hold" is far less
//! useful than "this property does not hold, and here is a packet that breaks
//! it, which you can paste into a test".

use biodivine_lib_bdd::Bdd;
use soteria_ir::{Field, SymbolTable};

use crate::header::Layout;

/// One point in the header space.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Packet {
    pub src: u32,
    pub dst: u32,
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    pub iif: u8,
    pub oif: u8,
}

impl Packet {
    /// Render for a report, naming interfaces where the table knows them.
    pub fn describe(&self, syms: &SymbolTable) -> String {
        let ip =
            |v: u32| format!("{}.{}.{}.{}", v >> 24, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff);
        let proto = match self.proto {
            1 => "icmp".to_string(),
            6 => "tcp".to_string(),
            17 => "udp".to_string(),
            other => other.to_string(),
        };
        let iface = syms.name_of(self.iif).map(|n| format!(" in {n}")).unwrap_or_default();
        // Ports are meaningless for protocols that have none; printing them
        // would invite someone to reproduce a packet that cannot exist.
        if self.proto == 1 {
            format!("{proto} {} -> {}{iface}", ip(self.src), ip(self.dst))
        } else {
            format!(
                "{proto} {}:{} -> {}:{}{iface}",
                ip(self.src),
                self.sport,
                ip(self.dst),
                self.dport
            )
        }
    }
}

/// Extract one packet from a non-empty set. `None` when the set is empty.
pub fn witness(layout: &Layout, set: &Bdd) -> Option<Packet> {
    let valuation = set.sat_witness()?;
    let field = |f: Field| -> u64 {
        let w = f.bits();
        let mut v = 0u64;
        for b in 0..w {
            if valuation.value(layout.var(f, b)) {
                v |= 1u64 << (w - 1 - b);
            }
        }
        v
    };
    Some(Packet {
        src: field(Field::SrcAddr) as u32,
        dst: field(Field::DstAddr) as u32,
        sport: field(Field::SrcPort) as u16,
        dport: field(Field::DstPort) as u16,
        proto: field(Field::Proto) as u8,
        iif: field(Field::IfIn) as u8,
        oif: field(Field::IfOut) as u8,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::VarOrder;

    #[test]
    fn an_empty_set_has_no_witness() {
        let l = Layout::default();
        assert!(witness(&l, &l.ff()).is_none());
    }

    #[test]
    fn a_witness_is_a_member_of_the_set() {
        for order in [VarOrder::FieldMajor, VarOrder::AddrInterleaved] {
            let l = Layout::new(order);
            let set = l
                .prefix(Field::SrcAddr, 0x0A01_0000, 16)
                .and(&l.eq(Field::DstAddr, 0x0A05_000E))
                .and(&l.eq(Field::DstPort, 502))
                .and(&l.eq(Field::Proto, 6));
            let p = witness(&l, &set).expect("non-empty set has a witness");

            assert_eq!(p.dst, 0x0A05_000E);
            assert_eq!(p.dport, 502);
            assert_eq!(p.proto, 6);
            assert_eq!(p.src >> 16, 0x0A01);

            // The strong check: rebuild the point and require it inside the set.
            let point = l
                .eq(Field::SrcAddr, u64::from(p.src))
                .and(&l.eq(Field::DstAddr, u64::from(p.dst)))
                .and(&l.eq(Field::SrcPort, u64::from(p.sport)))
                .and(&l.eq(Field::DstPort, u64::from(p.dport)))
                .and(&l.eq(Field::Proto, u64::from(p.proto)))
                .and(&l.eq(Field::IfIn, u64::from(p.iif)))
                .and(&l.eq(Field::IfOut, u64::from(p.oif)));
            assert!(point.and_not(&set).is_false(), "witness is outside the set");
        }
    }

    #[test]
    fn icmp_witnesses_do_not_print_ports() {
        let l = Layout::default();
        let set = l.eq(Field::Proto, 1).and(&l.eq(Field::DstAddr, 0x0A05_0001));
        let p = witness(&l, &set).unwrap();
        let text = p.describe(&SymbolTable::default());
        assert!(text.starts_with("icmp "), "{text}");
        assert!(!text.contains(':'), "icmp has no ports: {text}");
    }

    #[test]
    fn a_known_interface_is_named() {
        let l = Layout::default();
        let syms = SymbolTable::from_names(["eth0", "eth1"]).unwrap();
        let set = l.eq(Field::IfIn, 1).and(&l.eq(Field::Proto, 6));
        let p = witness(&l, &set).unwrap();
        assert!(p.describe(&syms).ends_with(" in eth1"), "{}", p.describe(&syms));
    }
}
