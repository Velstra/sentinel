//! The shipped sample and its account-preserving CLI adapter must agree.
#[test]
fn sample_network_and_cli_converge_without_deleting_the_installer_identity() {
    use crate::{config::Appliance, session::Session};
    let wanted = Appliance::from_toml(include_str!("../examples/quickstart.toml")).unwrap();
    let mut random = [0u8; 16];
    getrandom::getrandom(&mut random).unwrap();
    let dir = std::env::temp_dir().join(format!(
        "sentinel-quickstart-{:x}.toml",
        u128::from_ne_bytes(random)
    ));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("appliance.toml");
    let original=Appliance::from_toml("[system]\nhostname=\"installed\"\n[[system.group]]\nname=\"operators\"\npermission=\"read-write\"\n[[system.login]]\nusername=\"operator\"\ngroup=\"operators\"\n").unwrap();
    crate::session::persist_appliance(&original, &path, false).unwrap();
    let mut session = Session::load(&path).unwrap();
    for line in include_str!("../examples/quickstart.cli").lines() {
        let words = crate::repl::split_line(line);
        if words.first().is_some_and(|s| s == "set") {
            let args: Vec<_> = words.iter().skip(1).map(String::as_str).collect();
            session.set(&args).unwrap();
        }
    }
    let mut actual = session.commit().unwrap();
    assert_eq!(actual.system.logins.len(), 1);
    assert_eq!(actual.system.logins[0].username, "operator");
    actual.system.logins.clear();
    actual.system.groups.clear();
    actual.interfaces.retain(|i| i.zone.is_some());
    assert_eq!(actual.to_json().unwrap(), wanted.to_json().unwrap());
    std::fs::remove_dir_all(dir).unwrap();
}
