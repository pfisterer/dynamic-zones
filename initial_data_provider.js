(function () {
    try {
        console.log("Starting initial data provider...");

        console.log("Available API:", policy);

        // 1. Check if any policies are already stored
        const existingRules = policy.getAll();

        if (existingRules && existingRules.length > 0) {
            console.log(`Found ${existingRules.length} existing policy rules. Skipping seeding.`);
            return {
                success: true,
                message: `Database already contains ${existingRules.length} policy rules`,
                rulesCount: existingRules.length
            };
        }

        console.log("No existing policies found. Seeding database with dummy data...");

        // 2. Define dummy rules matching the Go structure
        const dummyRules = [
            {
                zone_pattern: "%u.users.dhbw.cloud",
                zone_soa: "users.dhbw.cloud",
                target_user_filter: "*@dhbw.de",
                allow_subdomains: true,
                sharing_allowed: false,
                description: "Automatic personal zones for DHBW users"
            },
            {
                zone_pattern: "some-project.dhbw.cloud",
                zone_soa: "dhbw.cloud",
                target_user_filter: "dennis.pfisterer@dhbw.de, clemens.martin@dhbw.de",
                allow_subdomains: true,
                sharing_allowed: true,
                description: "All DHBW users can manage a common project zone"
            },
            {
                zone_pattern: "%u.cloud.uni-luebeck.de",
                zone_soa: "cloud.uni-luebeck.de",
                target_user_filter: "*@uni-luebeck.de",
                allow_subdomains: true,
                sharing_allowed: false,
                description: "All Uni-Luebeck users can create subdomains"
            },
            // The dev user (root.admin@uni.example, run-development.sh) gets zones shaped like a busy admin's on prod: a personal zone, two extra zones under a shared name, and two shared team zones; scripts/dev-seed-zones.sh creates them with their subzones and co-owners.
            {
                zone_pattern: "%u.users.dhbw.site",
                zone_soa: "users.dhbw.site",
                target_user_filter: "*@uni.example, *@cs.example, *@bio.example",
                allow_subdomains: true,
                sharing_allowed: false,
                description: "Personal zones (dev)"
            },
            {
                zone_pattern: "test.pfisterer.users.dhbw.site",
                zone_soa: "users.dhbw.site",
                target_user_filter: "root.admin@uni.example",
                allow_subdomains: true,
                sharing_allowed: false,
                description: "Extra test zone (dev)"
            },
            {
                zone_pattern: "bigdata.pfisterer.users.dhbw.site",
                zone_soa: "users.dhbw.site",
                target_user_filter: "root.admin@uni.example",
                allow_subdomains: true,
                sharing_allowed: false,
                description: "Course zone (dev)"
            },
            {
                zone_pattern: "wi-ma.dhbw.site",
                zone_soa: "dhbw.site",
                target_user_filter: "root.admin@uni.example, admin@cs.example, faculty@cs.example",
                allow_subdomains: true,
                sharing_allowed: true,
                description: "Shared team zone (dev)"
            },
            {
                zone_pattern: "services.dhbw.cloud",
                zone_soa: "dhbw.cloud",
                target_user_filter: "root.admin@uni.example, admin@cs.example, faculty@bio.example",
                allow_subdomains: true,
                sharing_allowed: true,
                description: "Shared platform zone (dev)"
            }
        ];

        // 3. Create each rule
        const createdRules = [];
        for (const rule of dummyRules) {
            try {
                console.log(`Creating policy rule: ${rule.zone_pattern}`);
                const created = policy.createRule(rule);
                createdRules.push(created);
                console.log(`Successfully created rule with ID: ${created.id}`);
            } catch (error) {
                console.error(`Failed to create rule ${rule.zone_pattern}: ${error}`);
                throw error;
            }
        }

        console.log(`Successfully created ${createdRules.length} policy rules`);
        return {
            success: true,
            message: `Seeded database with ${createdRules.length} policy rules`,
            rulesCount: createdRules.length,
            rules: createdRules
        };

    } catch (error) {
        console.error(`Initial data provider failed: ${error}`);
        return {
            success: false,
            message: `Error during initialization: ${error}`,
            error: error.toString()
        };
    }
})();

