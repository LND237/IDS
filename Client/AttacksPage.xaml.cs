using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Windows.Devices.Lights.Effects;

namespace Client
{
    /// <summary>
    /// Interaction logic for AttacksPage.xaml
    /// </summary>
    public partial class AttacksPage : Page
    {
        private string IP;
        private string attacktype;
        private string startDate;
        private string endDate;
        private List<AttackLog> attackLogs;
        public AttacksPage()
        {
            InitializeComponent();
            attackLogs = MainWindow.GetDatabase().GetAttacksInLastNMinutes(MainWindow.LAST_DAY_AMOUNT_MINUTES);
            this.detailsItemsTopAttacks.ItemsSource = attackLogs;
        }

        private void ClearInputs()
        {
            SearchIPTextBox.Clear();
            attackTypeComboBox.SelectedIndex = -1;
            StartDate.Text = "";
            EndDate.Text = "";
        }


        private void ClearVariables()
        {
            IP = "";
            attacktype = "";
            startDate = "";
            endDate = "";
        }
        private void Search_Button_Click(object sender, RoutedEventArgs e)
        {
            string excpStr = "";
            MongoDBAttackLogger database = MainWindow.GetDatabase();
            List<AttackLog> attacks = database.getAllAttacks();
            this.IP = SearchIPTextBox.Text;
            this.attacktype = attackTypeComboBox.Text;
            this.startDate = StartDate.Text;
            this.endDate = EndDate.Text.ToString();

            //Checking the field of the ip
            if (this.IP != "")
            {
                try
                {
                    IP ip = new IP(this.IP); //for validating ip
                    attacks = database.GetAttackerIpAttacks(this.IP);
                }
                catch (Exception ex)
                {
                    excpStr += ex.Message + "\n";
                }
            }

            //Checking the starting date
            if(!string.IsNullOrEmpty(this.startDate))
            {
                try
                {
                    attacks = database.GetAttacksInLastNMinutes((int)DateTime.Parse(startDate).Subtract(new DateTime(1, 1, 1)).TotalSeconds);
                }
                catch
                {
                    excpStr += "INVALID START DATE!";
                }
            }

            //Checking the end date
            if (!string.IsNullOrEmpty(this.endDate))
            {
                try
                {
                    attacks = database.GetAttacksBeforeDate(DateTime.Parse(endDate));
                }
                catch
                {
                    excpStr += "INVALID END DATE!";
                }
            }

            //Checking the fields of the dates
            if (!string.IsNullOrEmpty(this.startDate) && !string.IsNullOrEmpty(this.endDate))
            {
                try
                {
                    if (DateTime.Parse(startDate) > DateTime.Parse(endDate))
                    {
                        excpStr += "START DATE MUST BE BEFORE END DATE!\n";
                    }
                }
                catch(Exception ex)
                {
                    excpStr = ex.Message + "\n";
                }

            }
            //Checking the attack type field
            if (!string.IsNullOrEmpty(this.attacktype))
            {
                attacks = AllAttacksWithType(attacks, this.attacktype);
            }
            if(excpStr != "")
            {
                MessageBox.Show(excpStr, "Error!", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            else
            {
                this.detailsItemsTopAttacks.ItemsSource = attacks;
            }
            ClearInputs();
            ClearVariables();
        }
        private List<AttackLog> AllAttacksWithType(List<AttackLog> attacks, string attackType)
        {
            const string DNS_HIJACKING_SHORT_NAME = "DNS";
            List<AttackLog> filteredAttacks = new List<AttackLog>();

            if (attackType.Equals("DNS hijacking"))
            {
                attackType = DNS_HIJACKING_SHORT_NAME;
            }

            //Going over the given attacks
            foreach (AttackLog attackLog in attacks) 
            {
                if (attackLog.AttackName.Equals(attackType))
                {
                    filteredAttacks.Add(attackLog);
                }
            }
            return filteredAttacks;
        }
        
    }
}
