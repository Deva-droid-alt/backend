# Generated by Django 4.2.17 on 2025-03-19 08:29

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('requests', '0013_alter_travelrequests_status'),
    ]

    operations = [
        migrations.AlterField(
            model_name='travelrequests',
            name='employee',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='travel_requests', to='requests.employee'),
        ),
        migrations.AlterField(
            model_name='travelrequests',
            name='manager',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='managed_travel_requests', to='requests.manager'),
        ),
        migrations.AlterField(
            model_name='travelrequests',
            name='purpose',
            field=models.TextField(),
        ),
        migrations.AlterField(
            model_name='travelrequests',
            name='resubmitted',
            field=models.BooleanField(default=False),
        ),
    ]
