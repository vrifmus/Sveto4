using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;

namespace Sveto4
{
    /// <summary>"Add exception…" window. Validation errors are shown inside the window (a user action).</summary>
    internal sealed class ExceptionDialog : Form
    {
        private readonly List<string> existingNames;
        private readonly TextBox name = new TextBox { Width = 320 };
        private readonly TextBox addresses = new TextBox { Width = 320 };
        private readonly TextBox program = new TextBox { Width = 320 };
        private readonly ComboBox protocol = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 100 };
        private readonly TextBox ports = new TextBox { Width = 320, Enabled = false };
        private readonly Label error = new Label { AutoSize = true, ForeColor = Color.Firebrick, MaximumSize = new Size(480, 0) };

        public ExceptionEntry Result { get; private set; }

        public ExceptionDialog(List<string> existingNames)
        {
            this.existingNames = existingNames;

            Text = "Add exception";
            Font = SystemFonts.MessageBoxFont;
            AutoScaleMode = AutoScaleMode.Dpi;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterScreen;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            Padding = new Padding(12);

            protocol.Items.AddRange(new object[] { "Any", "TCP", "UDP" });
            protocol.SelectedIndex = 0;
            protocol.SelectedIndexChanged += (s, e) => ports.Enabled = protocol.SelectedIndex != 0;

            var browse = new Button { Text = "…", AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink };
            browse.Click += (s, e) => Browse();

            var table = new TableLayoutPanel { AutoSize = true, ColumnCount = 3, Dock = DockStyle.Fill };
            AddRow(table, "Name:", name, null, "For example: SSH to VPS.");
            AddRow(table, "Address:", addresses, null, "IP addresses or subnets, comma-separated. Host names are not supported.");
            AddRow(table, "Program:", program, browse, "Empty: any program.");
            AddRow(table, "Protocol:", protocol, null, null);
            AddRow(table, "Ports:", ports, null, "Remote ports, e.g. 22 or 8000-8100. Empty: any port.");
            table.Controls.Add(error, 1, table.RowCount);
            table.SetColumnSpan(error, 2);
            table.RowCount++;

            var ok = new Button { Text = "Add", AutoSize = true, MinimumSize = new Size(80, 0) };
            var cancel = new Button { Text = "Cancel", AutoSize = true, MinimumSize = new Size(80, 0), DialogResult = DialogResult.Cancel };
            ok.Click += (s, e) => Accept();
            var buttons = new FlowLayoutPanel
            {
                FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill,
                Margin = new Padding(0, 8, 0, 0),
            };
            buttons.Controls.Add(cancel);
            buttons.Controls.Add(ok);
            table.Controls.Add(buttons, 0, table.RowCount);
            table.SetColumnSpan(buttons, 3);
            table.RowCount++;

            Controls.Add(table);
            AcceptButton = ok;
            CancelButton = cancel;
        }

        private static void AddRow(TableLayoutPanel table, string label, Control field, Control extra, string hint)
        {
            var row = table.RowCount;
            table.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 6, 8, 0) }, 0, row);
            table.Controls.Add(field, 1, row);
            if (extra != null) table.Controls.Add(extra, 2, row);
            row++;
            if (hint != null)
            {
                var hintLabel = new Label
                {
                    Text = hint, AutoSize = true, ForeColor = SystemColors.GrayText,
                    MaximumSize = new Size(360, 0), Margin = new Padding(3, 0, 3, 6),
                };
                table.Controls.Add(hintLabel, 1, row);
                table.SetColumnSpan(hintLabel, 2);
                row++;
            }
            table.RowCount = row;
        }

        private void Browse()
        {
            using (var dialog = new OpenFileDialog { Title = "Program", Filter = "Programs (*.exe)|*.exe" })
            {
                if (dialog.ShowDialog(this) == DialogResult.OK) program.Text = dialog.FileName;
            }
        }

        private void Accept()
        {
            try
            {
                var proto = protocol.SelectedIndex == 1 ? ExceptionProtocol.Tcp
                          : protocol.SelectedIndex == 2 ? ExceptionProtocol.Udp
                          : ExceptionProtocol.Any;
                Result = Exceptions.Create(name.Text, addresses.Text, program.Text, proto,
                                           ports.Enabled ? ports.Text : null, existingNames);
                DialogResult = DialogResult.OK;
            }
            catch (ExceptionValidationError ex)
            {
                error.Text = ex.Message;
            }
        }
    }
}
