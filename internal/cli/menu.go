package cli

import (
	"charm.land/huh/v2"
	"github.com/RasmusLauritsen/hmesh/internal/router"
)

func (a *app) menu() error {
	if !a.canPrompt() {
		return router.Fail("usage", "interactive menu needs a terminal; use a subcommand (see hmesh --help)")
	}
	var action string
	form := huh.NewForm(huh.NewGroup(huh.NewSelect[string]().Title("hmesh — "+a.settings.Router).Options(
		huh.NewOption("Router status", "status"), huh.NewOption("Devices", "devices"), huh.NewOption("Mesh topology", "topology"),
		huh.NewOption("List DHCP reservations", "reservations"), huh.NewOption("Create DHCP reservation", "create"),
		huh.NewOption("Update DHCP reservation", "update"), huh.NewOption("Delete DHCP reservation", "delete"),
		huh.NewOption("Show DNS configuration (read-only)", "dns"), huh.NewOption("List port-forward mappings (read-only)", "port-forward"),
		huh.NewOption("Save login to OS keyring", "login"), huh.NewOption("Quit", "quit"),
	).Value(&action)))
	if err := form.WithInput(a.in).WithOutput(a.errOut).Run(); err != nil {
		return router.Fail("usage", "menu canceled")
	}
	switch action {
	case "quit":
		return nil
	case "login":
		return a.login()
	case "dns":
		return a.dns()
	case "create", "update", "delete":
		var mac, ip, state string
		fields := []huh.Field{huh.NewInput().Title("Device MAC address").Value(&mac)}
		if action != "delete" {
			label := "Reserved IPv4"
			if action == "update" {
				label += " (blank to keep existing)"
			}
			fields = append(fields, huh.NewInput().Title(label).Value(&ip))
			options := []huh.Option[string]{huh.NewOption("Enabled", "true"), huh.NewOption("Disabled", "false")}
			if action == "update" {
				options = append([]huh.Option[string]{huh.NewOption("Keep existing state", "keep")}, options...)
			}
			fields = append(fields, huh.NewSelect[string]().Title("Reservation state").Options(options...).Value(&state))
		}
		if err := huh.NewForm(huh.NewGroup(fields...)).WithInput(a.in).WithOutput(a.errOut).Run(); err != nil {
			return router.Fail("usage", "reservation entry canceled")
		}
		var enabled *bool
		if state == "true" || state == "false" {
			b := state == "true"
			enabled = &b
		}
		return a.mutate(action, mac, ip, enabled)
	default:
		return a.read(action)
	}
}
