﻿using System;
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

namespace Client
{
    /// <summary>
    /// Interaction logic for AttacksPage.xaml
    /// </summary>
    public partial class AttacksPage : Page
    {
        private string IP;
        private string attacktype;
        private DateTime startDate;
        private DateTime endDate;
        public AttacksPage()
        {
            InitializeComponent();
        }


        private void Search_Button_Click(object sender, RoutedEventArgs e)
        {
            this.IP = SearchIPTextBox.Text;
            this.attacktype = attackTypeComboBox.Text;
            this.startDate = DateTime.Parse(StartDate.Text);
            this.endDate = DateTime.Parse(EndDate.Text);
            SearchIPTextBox.Clear();
            attackTypeComboBox.SelectedIndex = -1;
            StartDate.Text = "";
            EndDate.Text = "";
        }
        
    }
}
